/*
   muonsocks - multithreaded, small, efficient SOCKS(5|4a) server.

   Copyright (C) 2017 rofl0r.
   Copyright 2020-2026 Nicholas J. Kain

   SPDX-License-Identifier: MIT

   This program is derived from rofl0r's excellent microsocks.
*/

#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <poll.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>
#include <stdatomic.h>
#include "sockunion.h"
#include "nk/privs.h"

#if defined(__GNUC__) || defined(__clang__)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define LIKELY(x) __builtin_expect(!!(x), 1)
#else
#define UNLIKELY(x) (x)
#define LIKELY(x) (x)
#endif

#define THREAD_STACK_SIZE (64 * 1024)

// Support lagging platforms like OSX.
#if (defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFlyBSD__))
#define MU_SOCKET_OPTS (SOCK_CLOEXEC|SOCK_NONBLOCK)
static int socket_set_nonblock(int fd) { (void)fd; return 0; }
static int socket_set_cloexec(int fd) { (void)fd; return 0; }
#define mu_accept(...) accept4(__VA_ARGS__, MU_SOCKET_OPTS)
#else
#define MU_SOCKET_OPTS (0)
static int socket_set_nonblock(int fd)
{
    int ret = 0;
    int flags = fcntl(fd, F_GETFL);
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        ret = -1;
        dprintf(2, "failed to set O_NONBLOCK on socket\n");
    }
    return ret;
}
static int socket_set_cloexec(int fd)
{
    int ret = 0;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
        ret = -1;
        dprintf(2, "failed to set FD_CLOEXEC on socket\n");
    }
    return ret;
}
#define mu_accept(...) accept(__VA_ARGS__)
#endif

#ifdef __APPLE__
static inline void *reallocarray(void *ptr, size_t nmemb, size_t size)
{
    if ((nmemb >= SIZE_MAX || size >= SIZE_MAX) && nmemb > 0 && SIZE_MAX / nmemb < size) {
        errno = ENOMEM;
        return NULL;
    }
    return realloc(ptr, nmemb * size);
}
#endif

// Time spent trying to connect to an IP address before failing or
// attempting another IP (for hosts that resolve to multiple IPs).
#define CONNECTION_TIMEOUT_MS 2000

// Time to wait before queueing a new connection attempt for hosts
// with multiple IPs.
#define CONNECTION_DELAY_MS 250

// Inactive connections are reaped after 15 min to free resources.
// Usually programs send keep-alive packets so this should only happen
// when a connection is really unused.
#define IDLE_TIMEOUT_MS (60*15*1000)
// A 10s inactivity timeout is used during the initial negotiation phase
#define HANDSHAKE_TIMEOUT_MS (10*1000)

// BUF_SIZE is set to a multiple of a typical 1500 MTU
// minus options-free IPv6 (40) and TCP (20) headers
#define BUF_SIZE 50400

// struct thread is allocated in blocks
#define THREAD_BLOCK_SIZE 64

// Atomically: assigns ASSIGN = TOP and then sets TOP = NEW_TOP.
#define LIST_EXCHANGE_TOP(TOP, ASSIGN, NEW_TOP) do { for (;;) {  \
    (ASSIGN) = (TOP);                                           \
    if (LIKELY(atomic_compare_exchange_strong(&(TOP), &(ASSIGN), (NEW_TOP)))) break; \
    }} while (0)

struct client {
    union sockaddr_union addr;
    int fd;
    int socksver;
};

struct server {
    const char *listenip;
    int fd;
};

struct thread {
    pthread_t pt;
    struct client client;
    struct thread *gc_next;
};

struct bandst {
    int fam;
    struct in_addr addr4;
    struct in6_addr addr6;
    uint32_t mask;
};

static char *g_user_id;
static char *g_chroot;
static char *g_auth_user;
static char *g_auth_pass;
static bool allow_ipv4 = true;
static bool allow_ipv6 = true;
static bool use_auth_ips = false;
static bool g_logging = false;
static size_t nauth_ips;
static size_t nban_dest;
static union sockaddr_union *auth_ips;
static struct bandst *ban_dest;
static pthread_mutex_t auth_ips_mtx;
static union sockaddr_union bind_addr;

static _Atomic (struct thread *) g_gc_list;
// This is only ever accessed on the main listening thread.
static struct thread *g_freelist;

enum authmethod {
    AM_NO_AUTH = 0,
    AM_GSSAPI = 1,
    AM_USERNAME = 2,
    AM_INVALID = -1
};

enum errorcode {
    EC_SUCCESS = 0,
    EC_GENERAL_FAILURE = 1,
    EC_NOT_ALLOWED = 2,
    EC_NET_UNREACHABLE = 3,
    EC_HOST_UNREACHABLE = 4,
    EC_CONN_REFUSED = 5,
    EC_TTL_EXPIRED = 6,
    EC_COMMAND_NOT_SUPPORTED = 7,
    EC_ADDRESSTYPE_NOT_SUPPORTED = 8,
};

/* we log to stderr because it's not using line buffering, i.e. malloc which would need
   locking when called from different threads. for the same reason we use dprintf,
   which writes directly to an fd. */
static void dolog(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vdprintf(2, format, args);
    va_end(args);
}

static int resolve(const char *host, unsigned short port, int fam, struct addrinfo** addr) {
    struct addrinfo hints = {
        .ai_family = fam,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE,
    };
    char port_buf[8];
    int sz = snprintf(port_buf, sizeof port_buf, "%u", port);
    if (sz < 0 || (size_t)sz >= sizeof port_buf) return EAI_SYSTEM;
    return getaddrinfo(host, port_buf, &hints, addr);
}

static int resolve_sa(const char *host, unsigned short port, union sockaddr_union *res) {
    struct addrinfo *ainfo = 0;
    int ret;
    SOCKADDR_UNION_AF(res) = AF_UNSPEC;
    if ((ret = resolve(host, port, AF_UNSPEC, &ainfo))) return ret;
    memcpy(res, ainfo->ai_addr, ainfo->ai_addrlen);
    freeaddrinfo(ainfo);
    return 0;
}

static int bindtoip(int fd, union sockaddr_union *bindaddr) {
    socklen_t sz = SOCKADDR_UNION_LENGTH(bindaddr);
    if (!sz) return 0;
    int flags = 1;
    in_port_t bindport = !!SOCKADDR_UNION_PORT(bindaddr);
#ifdef __linux__
    int level = bindport ? SOL_SOCKET : IPPROTO_IP;
    int optname = bindport ? SO_REUSEADDR : IP_BIND_ADDRESS_NO_PORT;
    if (setsockopt(fd, level, optname, &flags, sizeof flags) < 0)
        dprintf(2, "failed to set %s on client socket\n", bindport ? "SO_REUSEADDR" : "IP_BIND_ADDRESS_NO_PORT");
#else
    if (bindport) {
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof flags) < 0)
            dprintf(2, "failed to set SO_REUSEADDR on client socket\n");
    }
#endif
    return bind(fd, (struct sockaddr *)bindaddr, sz);
}

static struct thread *grow_struct_thread(void)
{
    struct thread *t;
    t = malloc(THREAD_BLOCK_SIZE * sizeof(struct thread));
    if (UNLIKELY(!t)) return NULL;

    size_t i = 1;
    for (; i < THREAD_BLOCK_SIZE - 1; ++i)
        t[i].gc_next = t + i + 1;
    t[i].gc_next = g_freelist;
    g_freelist = t + 1;
    return t;
}

static void free_struct_thread(struct thread *t)
{
    t->gc_next = g_freelist;
    g_freelist = t;
}

static void gc_threads(void) {
    if (atomic_load(&g_gc_list)) {
        struct thread *local_list = atomic_exchange(&g_gc_list, NULL);

        while (local_list) {
            struct thread *t = local_list;
            local_list = local_list->gc_next;
            pthread_join(t->pt, 0);
            free_struct_thread(t);
        }
    }
}

static int server_waitclient(struct server *server, struct client* client)
{
    socklen_t clen;
retry:
    clen = sizeof client->addr;
    client->fd = mu_accept(server->fd, (struct sockaddr *)&client->addr, &clen);
    if (client->fd == -1) {
        switch (errno) {
        case EINTR: goto retry;
        // Resource limit reached errors.
        case EMFILE: case ENFILE: case ENOBUFS: case ENOMEM: return -2;
        default: return -1;
        }
    }
    if (socket_set_cloexec(client->fd) == -1 || socket_set_nonblock(client->fd) == -1) {
        close(client->fd);
        return -1;
    }
    int flags = 1;
    if (setsockopt(client->fd, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof flags) < 0)
        dprintf(2, "failed to set TCP_NODELAY on client socket\n");
    return 0;
}

static void delay10ms(void)
{
    // Prevent busy-spin when fd limit is reached
    struct timespec rem, tw = { .tv_nsec = 10000000 }; // 10ms
ns_again:
    if (nanosleep(&tw, &rem)) {
        if (errno == EINTR) {
            tw = rem;
            goto ns_again;
        }
        abort();
    }
}

static int server_setup(struct server *server, unsigned short port) {
    struct addrinfo *ainfo = NULL;
    if (resolve(server->listenip, port, AF_UNSPEC, &ainfo)) return -1;
    int listenfd = -1;
    for (struct addrinfo *p = ainfo; p; p = p->ai_next) {
        if ((listenfd = socket(p->ai_family, p->ai_socktype|MU_SOCKET_OPTS, p->ai_protocol)) < 0)
            continue;
        if (socket_set_nonblock(listenfd) < 0 || socket_set_cloexec(listenfd) < 0) {
            close(listenfd);
            listenfd = -1;
            continue;
        }
        int yes = 1;
        if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) < 0) {
            dprintf(2, "failed to set SO_REUSEADDR on listen socket\n");
        }
        if (bind(listenfd, p->ai_addr, p->ai_addrlen) < 0) {
            close(listenfd);
            listenfd = -1;
            continue;
        }
        break;
    }
    int ret = 0;
    if (listenfd < 0) {
        ret = -2;
    } else if (listen(listenfd, SOMAXCONN) < 0) {
        close(listenfd);
        ret = -3;
    } else {
        server->fd = listenfd;
    }
    freeaddrinfo(ainfo);
    return ret;
}

static ssize_t copywrite(int fd, const char *buf, ssize_t buflen, int timeout);

static int is_authed(union sockaddr_union *client, union sockaddr_union *authedip) {
    int af = SOCKADDR_UNION_AF(authedip);
    if (af == SOCKADDR_UNION_AF(client)) {
        size_t cmpbytes = af == AF_INET ? 4 : 16;
        const void *cmp1 = SOCKADDR_UNION_ADDRESS(client);
        const void *cmp2 = SOCKADDR_UNION_ADDRESS(authedip);
        if (!memcmp(cmp1, cmp2, cmpbytes)) return 1;
    }
    return 0;
}

static int is_in_authed_list(union sockaddr_union *caddr) {
    for (size_t i = 0; i < nauth_ips; ++i) {
        if (is_authed(caddr, &auth_ips[i])) return 1;
    }
    return 0;
}

static void add_auth_ip(union sockaddr_union *caddr) {
    auth_ips = reallocarray(auth_ips, nauth_ips + 1, sizeof(union sockaddr_union));
    if (!auth_ips) perror("reallocarray");
    memcpy(auth_ips + (nauth_ips++), caddr, sizeof *caddr);
}

static int send_auth_response(int fd, char version, enum authmethod method) {
    char buf[2] = { version, method };
    ssize_t blen = sizeof buf;
    return copywrite(fd, buf, sizeof buf, HANDSHAKE_TIMEOUT_MS) == blen ? blen : -1;
}

static int send_error(const struct client *c, int fd, enum errorcode ec) {
    struct sockaddr_storage srcaddr = { .ss_family = AF_INET }; // for non-EC_SUCCESS case
    if (ec == EC_SUCCESS) {
        socklen_t srcaddrlen = sizeof srcaddr;
        if (getsockname(fd, (struct sockaddr *)&srcaddr, &srcaddrlen) == -1) return -1;
    }
    char b[24];
    ssize_t blen;
    if (c->socksver == 5) {
        b[0] = 5;
        b[1] = ec;
        b[2] = 0;
        if (srcaddr.ss_family == AF_INET) {
            b[3] = 1;
            const struct sockaddr_in *sa = (struct sockaddr_in *)&srcaddr;
            memcpy(b + 4, &sa->sin_addr, 4);
            memcpy(b + 8, &sa->sin_port, 2);
            blen = 10;
        } else {
            b[3] = 4;
            const struct sockaddr_in6 *sa =(struct sockaddr_in6 *) &srcaddr;
            memcpy(b + 4, &sa->sin6_addr, 16);
            memcpy(b + 20, &sa->sin6_port, 2);
            blen = 22;
        }
    } else if (c->socksver == 4) {
        if (srcaddr.ss_family != AF_INET) {
            // We could return -1 here, except it would break connections in
            // the case that the client requested a destination by DNS address
            // and the SOCKS proxy connected to that host via IPv6.  So, the
            // lesser evil is to just lie and report a zero IP.
            memset(&srcaddr, 0, sizeof srcaddr);
        }
        const struct sockaddr_in *sa = (struct sockaddr_in *)&srcaddr;
        b[0] = 0;
        b[1] = ec == EC_SUCCESS ? (char)0x5a : (char)0x5b;
        memcpy(b + 2, &sa->sin_port, 2);
        memcpy(b + 4, &sa->sin_addr, 4);
        blen = 8;
    } else {
        return -1;
    }
    return copywrite(fd, b, blen, HANDSHAKE_TIMEOUT_MS) == blen ? blen : -1;
}

struct socksctx {
    char namebuf[256];
    struct addrinfo *remote;
    enum errorcode errc;
    unsigned short port;
};

struct srstats
{
    size_t bsent;
    size_t brecv;
};

static void log_dc(int clientfd, const char *clientname, const struct socksctx *ctx, const struct srstats *sr)
{
    if (!g_logging) return;
    dolog("client[%d] %s: disconnect from %s:%d sent:%zu recv:%zu\n", clientfd, clientname,
          ctx->namebuf, ctx->port, sr->bsent, sr->brecv);
}

static ssize_t copywrite(int fd, const char *buf, ssize_t buflen, int timeout)
{
    ssize_t sent = 0;
    while (sent < buflen) {
        ssize_t m = write(fd, buf+sent, (size_t)(buflen-sent));
        if (m > 0) {
            sent += m;
        } else if (m < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            poll_again:;
                int r = poll(&pfd, 1, timeout);
                if (UNLIKELY(r == 0)) return -1;
                if (UNLIKELY(r < 0)) {
                    if (errno == EINTR) goto poll_again;
                    return -1;
                }
                if (UNLIKELY(r > 0 && (pfd.revents & (POLLERR|POLLHUP)))) return -1;
                continue;
            }
            if (errno == EINTR) continue;
            return -1;
        }
    }
    return sent;
}

// 2 = no data available
// 1 = read and wrote data
// 0 = disconnect
// -1 = error
static int copyread(int in_fd, int out_fd, char *buf, size_t *counter)
{
    ssize_t n = read(in_fd, buf, BUF_SIZE);
    if (n == 0) {
        shutdown(out_fd, SHUT_WR);
        return 0;
    } else if (n < 0) {
        switch (errno) {
        case EINTR: return 1; // zero-size read/write
        case EAGAIN: return 2; // no data available
        default: return -1;
        }
    }
    ssize_t sent = copywrite(out_fd, buf, n, IDLE_TIMEOUT_MS);
    if (sent < 0) return -1;
    if (counter) *counter += (size_t)sent;
    return 1;
}

static void copyloop(int fd1, int fd2, const char *clientname, const struct socksctx *ctx)
{
    char buf[BUF_SIZE];
    struct pollfd fds[2] = {
        { fd1, POLLIN, 0},
        { fd2, POLLIN, 0},
    };
    struct srstats sr = { 0 };

    for (;;) {
        int pr = poll(fds, 2, IDLE_TIMEOUT_MS);
        if (UNLIKELY(pr <= 0)) {
            if (pr == -1) {
                if (errno == EINTR) continue;
                perror("poll");
            }
            break;
        }

        if (UNLIKELY(fds[0].revents & (POLLERR|POLLHUP))) break;
        if (UNLIKELY(fds[1].revents & (POLLERR|POLLHUP))) break;

        int ra = fds[0].revents & POLLIN, rb = fds[1].revents & POLLIN;
        do {
            if (fds[0].revents & POLLIN) {
                ra = copyread(fd1, fd2, buf, &sr.bsent);
                if (ra != 1) fds[0].revents &= ~POLLIN;
                if (UNLIKELY(ra < 0)) break;
                if (UNLIKELY(ra == 0)) fds[0].events &= ~POLLIN;
            }
            if (fds[1].revents & POLLIN) {
                rb = copyread(fd2, fd1, buf, &sr.brecv);
                if (rb != 1) fds[1].revents &= ~POLLIN;
                if (UNLIKELY(rb < 0)) break;
                if (UNLIKELY(rb == 0)) fds[1].events &= ~POLLIN;
            }
        } while (ra == 1 || rb == 1);
        if (UNLIKELY(!(fds[0].events & POLLIN) && !(fds[1].events & POLLIN))) break;
    }
    log_dc(fd1, clientname, ctx, &sr);
}

static bool extend_cbuf(const struct thread *t, char *buf, size_t *buflen)
{
    for (;;) {
        struct pollfd pfd = { .fd = t->client.fd, .events = POLLIN };
        int r = poll(&pfd, 1, HANDSHAKE_TIMEOUT_MS);
        if (UNLIKELY(r == 0)) return false;
        if (UNLIKELY(r < 0)) {
            if (errno == EINTR) continue;
            return false;
        }
        if (UNLIKELY(r > 0 && (pfd.revents & (POLLERR|POLLHUP)))) return false;
    read_again:;
        ssize_t n = read(t->client.fd, buf + *buflen, BUF_SIZE - *buflen);
        if (n == 0) {
            return false;
        } else if (n < 0) {
            if (errno == EINTR) goto read_again;
            return false;
        }
        *buflen += (size_t)n;
        return true;
    }
}

#define EXTEND_BUF() do { if (!extend_cbuf(t, buf, &buflen)) return -1; } while (0)
#define RESET_BUF() do { buflen = 0; } while (0)

static bool is_banned(int family, const struct addrinfo *remote)
{
    for (size_t i = 0; i < nban_dest; ++i) {
        if (ban_dest[i].fam == family) {
            unsigned char abuf[16], bbuf[16];
            size_t addrsize = family == AF_INET ? 4 : 16;
            struct sockaddr_in *ai4 = (struct sockaddr_in *)remote->ai_addr;
            struct sockaddr_in6 *ai6 = (struct sockaddr_in6 *)remote->ai_addr;
            memcpy(abuf, family == AF_INET ? (const void *)&ai4->sin_addr
                                           : (const void *)&ai6->sin6_addr, addrsize);
            memcpy(bbuf, family == AF_INET ? (const void *)&ban_dest[i].addr4
                                           : (const void *)&ban_dest[i].addr6, addrsize);
            unsigned char *p = abuf, *q = bbuf;
            uint32_t m = ban_dest[i].mask;
            if (family == AF_INET6 && m > 128) m = 128;
            if (family == AF_INET && m > 32) m = 32;
            for (;m >= 8; ++p, ++q, m -= 8) {
                if (*p != *q) return false;
            }
            if (m > 0) {
                assert(m < 8);
                unsigned char c = 0xffu << (8 - m);
                *p &= c;
                *q &= c;
                if (*p != *q) return false;
            }
            return true;
        }
    }
    return false;
}

static void clientthread_cleanup(struct thread *t)
{
    close(t->client.fd);
    t->client.fd = -1;
    LIST_EXCHANGE_TOP(g_gc_list, t->gc_next, t);
}

static int parse_socksreq(struct thread *t, struct socksctx *ctx)
{
    char buf[1024];
    size_t buflen = 0;
    enum authmethod am = AM_INVALID;
    int fam = AF_UNSPEC;

    EXTEND_BUF();

    t->client.socksver = buf[0];
    if (LIKELY(t->client.socksver == 5)) {
        while (buflen < 2) { EXTEND_BUF(); }
        size_t n_methods = buf[1] >= 0 ? (size_t)buf[1] : 0;
        while (buflen < 2 + n_methods) { EXTEND_BUF(); }
        for (size_t i = 0; i < n_methods; ++i) {
            if (buf[2 + i] == AM_NO_AUTH) {
                if (!g_auth_user) {
                    am = AM_NO_AUTH;
                    break;
                } else if (use_auth_ips) {
                    bool authed = 0;
                    if (UNLIKELY(pthread_mutex_lock(&auth_ips_mtx))) abort();
                    authed = is_in_authed_list(&t->client.addr);
                    if (UNLIKELY(pthread_mutex_unlock(&auth_ips_mtx))) abort();
                    if (authed) {
                        am = AM_NO_AUTH;
                        break;
                    }
                }
            } else if (buf[2 + i] == AM_USERNAME) {
                if (g_auth_user) {
                    am = AM_USERNAME;
                    break;
                }
            }
        }
        if (am == AM_INVALID) return -1;

        RESET_BUF();
        if (send_auth_response(t->client.fd, 5, am) < 0) return -1;
        if (am == AM_USERNAME) {
            while (buflen < 5) { EXTEND_BUF(); }
            if (buf[0] != 1) return -1;
            unsigned ulen, plen;
            ulen = buf[1] >= 0 ? (unsigned)buf[1] : 0;
            while (buflen < 2 + ulen + 2) { EXTEND_BUF(); }
            plen = buf[2 + ulen] >= 0 ? (unsigned)buf[2 + ulen] : 0;
            while (buflen < 2 + ulen + 1 + plen) { EXTEND_BUF(); }
            char user[256], pass[256];
            memcpy(user, buf + 2, ulen);
            memcpy(pass, buf + 2 + ulen + 1, plen);
            user[ulen] = 0;
            pass[plen] = 0;
            bool allow = !strcmp(user, g_auth_user) && !strcmp(pass, g_auth_pass);
            if (!allow) return -1;
            if (use_auth_ips) {
                if (UNLIKELY(pthread_mutex_lock(&auth_ips_mtx))) abort();
                if (!is_in_authed_list(&t->client.addr))
                    add_auth_ip(&t->client.addr);
                if (UNLIKELY(pthread_mutex_unlock(&auth_ips_mtx))) abort();
            }
            if (send_auth_response(t->client.fd, 1, am) < 0) return -1;
            RESET_BUF();
        }

        // Now we're done with the authentication negotiations.
        while (buflen < 5) { EXTEND_BUF(); }
        if (UNLIKELY(buf[0] != 5)) return -2;
        if (UNLIKELY(buf[1] != 1)) {
            ctx->errc = EC_COMMAND_NOT_SUPPORTED;
            return -2;
        }
        if (UNLIKELY(buf[2] != 0)) return -2;

        size_t minlen;
        if (buf[3] == 3) {
            size_t l = buf[4] >= 0 ? (size_t)buf[4] : 0;
            minlen = 4 + 1 + l + 2;
            while (buflen < minlen) { EXTEND_BUF(); }
            memcpy(ctx->namebuf, buf + 4 + 1, l);
            ctx->namebuf[l] = 0;
        } else {
            int af;
            if (buf[3] == 1) {
                af = AF_INET;
                minlen = 4 + 4 + 2;
            } else if (buf[3] == 4) {
                af = AF_INET6;
                minlen = 4 + 16 + 2;
            } else {
                ctx->errc = EC_COMMAND_NOT_SUPPORTED;
                return -2;
            }
            while (buflen < minlen) { EXTEND_BUF(); }
            if (ctx->namebuf != inet_ntop(af, buf + 4, ctx->namebuf, sizeof ctx->namebuf)) {
                return -2;
            }
        }
        memcpy(&ctx->port, buf + minlen - 2, 2);
        ctx->port = ntohs(ctx->port);
        if (!allow_ipv4) fam = AF_INET6;
        if (!allow_ipv6) fam = AF_INET;
    } else if (t->client.socksver == 4) {
        if (g_auth_pass) return -2;
        if (!allow_ipv4) {
            ctx->errc = EC_ADDRESSTYPE_NOT_SUPPORTED;
            return -2;
        }

        while (buflen < 9) { EXTEND_BUF(); }
        if (buf[0] != 4) return -2;
        if (buf[1] != 1) {
            ctx->errc = EC_COMMAND_NOT_SUPPORTED;
            return -2;
        }
        memcpy(&ctx->port, buf + 2, 2);
        ctx->port = ntohs(ctx->port);

        bool is_dns = false;
        if (buf[4] == 0 && buf[5] == 0 && buf[6] == 0 && buf[7] != 0) {
            is_dns = true;
        } else {
            if (ctx->namebuf != inet_ntop(AF_INET, buf + 4, ctx->namebuf, sizeof ctx->namebuf)) {
                return -2;
            }
        }
        size_t i = 8;
        for (;;++i) {
            // Here we just skip the userid for now
            if (i > BUF_SIZE / 2) return -2;
            while (buflen < i + 1) { EXTEND_BUF(); }
            if (buf[i] == 0) { ++i; break; }
        }
        if (is_dns) {
            size_t buf_start = i;
            for (;;++i) {
                if (i - buf_start > sizeof ctx->namebuf - 1) return -2;
                while (buflen < i + 1) { EXTEND_BUF(); }
                if (buf[i] == 0) {
                    memcpy(ctx->namebuf, buf + buf_start, i - buf_start);
                    ctx->namebuf[i - buf_start] = 0;
                    break;
                }
            }
        }
        fam = AF_INET;
    } else {
        return -1;
    }
    /* there's no suitable errorcode in rfc1928 for dns lookup failure */
    if (UNLIKELY(resolve(ctx->namebuf, ctx->port, fam, &ctx->remote))) return -2;
    return 0;
}

static int client_connect(const struct addrinfo *addr, bool *connected)
{
    int fd = -1;
    *connected = false;
    fd = socket(addr->ai_family, SOCK_STREAM|MU_SOCKET_OPTS, addr->ai_protocol);
    if (UNLIKELY(fd == -1)) return fd;
    if (socket_set_nonblock(fd) == -1 || socket_set_cloexec(fd) == -1) goto fail;

    if (UNLIKELY(SOCKADDR_UNION_AF(&bind_addr) != AF_UNSPEC && bindtoip(fd, &bind_addr) == -1)) goto fail;

connect_again:
    if (connect(fd, addr->ai_addr, addr->ai_addrlen)) {
        if (errno != EINPROGRESS) {
            if (errno == EINTR) goto connect_again;
            goto fail;
        }
    } else {
        *connected = true;
    }
    return fd;
fail:
    close(fd);
    return -1;
}

static struct addrinfo *pull_addr(struct addrinfo **addr, const struct socksctx *ctx)
{
    struct addrinfo *ret = NULL;
    for (; *addr; *addr = (*addr)->ai_next) {
        if (!allow_ipv4 && (*addr)->ai_family == AF_INET) continue;
        if (!allow_ipv6 && (*addr)->ai_family == AF_INET6) continue;
        if (UNLIKELY(is_banned((*addr)->ai_family, ctx->remote))) continue;
        ret = *addr;
        *addr = (*addr)->ai_next;
        break;
    }
    return ret;
}

static inline bool connect_timed_out(const struct timespec *start, const struct timespec *end)
{
    return ((end->tv_sec - start->tv_sec) * 1000) +
           ((end->tv_nsec - start->tv_nsec) / 1000000) >= CONNECTION_TIMEOUT_MS;
}

static bool connect_errored(int fd)
{
    int serr = 0;
    socklen_t slen = sizeof serr;
    return getsockopt(fd, SOL_SOCKET, SO_ERROR, &serr, &slen) < 0 || serr;
}

// -2  => no more addresses to try
// -1  => connect queued
// >=0 => connect immediate success
#define CLOSEFD(x) do { close(pfd[(x)].fd); pfd[(x)].fd = -1; } while (0)
static int queue_connect(struct addrinfo **addr, struct socksctx *ctx,
                         struct timespec *spawn_ts, struct pollfd *pfd)
{
    assert(pfd[0].fd == -1 || pfd[1].fd == -1 || pfd[2].fd == -1 || pfd[3].fd == -1
           || pfd[4].fd == -1 || pfd[5].fd == -1);
    for (;;) {
        struct addrinfo *caddr = pull_addr(addr, ctx);
        if (!caddr) return -2;
        bool connected;
        int fd = client_connect(caddr, &connected);
        if (fd == -1) continue;
        if (connected) {
            for (size_t i = 0; i < 6; ++i) CLOSEFD(i);
            return fd;
        }
        int i = 0;
        for (; i < 6; ++i) if (pfd[i].fd == -1) break;
        pfd[i].fd = fd;
        clock_gettime(CLOCK_MONOTONIC, &spawn_ts[i]);
        return -1;
    }
}

static void* clientthread(void *data) {
    struct thread *t = (struct thread *)data;
    struct socksctx ctx = { .errc = EC_GENERAL_FAILURE };
    char clientname[256] = { 0 };

    int r = parse_socksreq(t, &ctx);
    if (UNLIKELY(r == -1)) goto out0;
    if (UNLIKELY(r == -2)) goto err0;

    if (UNLIKELY(!allow_ipv6 && ctx.remote->ai_addr->sa_family == AF_INET6)) {
        ctx.errc = EC_ADDRESSTYPE_NOT_SUPPORTED;
        goto err1;
    }
    if (UNLIKELY(!allow_ipv4 && ctx.remote->ai_addr->sa_family == AF_INET)) {
        ctx.errc = EC_ADDRESSTYPE_NOT_SUPPORTED;
        goto err1;
    }
    struct addrinfo *addr = ctx.remote;
    int fd = -1;
    struct pollfd pfd[6] = {
        { .fd = -1, .events = POLLOUT },
        { .fd = -1, .events = POLLOUT },
        { .fd = -1, .events = POLLOUT },
        { .fd = -1, .events = POLLOUT },
        { .fd = -1, .events = POLLOUT },
        { .fd = -1, .events = POLLOUT },
    };
    struct timespec spawn_ts[6] = {0};

    goto jumpstart;
    while (pfd[0].fd >= 0 || pfd[1].fd >= 0 || pfd[2].fd >= 0
           || pfd[3].fd >= 0 || pfd[4].fd >= 0 || pfd[5].fd >= 0) {
        struct timespec poll_ts;
        clock_gettime(CLOCK_MONOTONIC, &poll_ts);
        r = poll(pfd, 6, CONNECTION_DELAY_MS); // fixed timeout so we regularly try to queue new addrs
        if (r > 0) {
            for (size_t i = 0; i < 6; ++i) {
                if (pfd[i].revents & POLLOUT) {
                    if (connect_errored(pfd[i].fd)) {
                        CLOSEFD(i);
                    } else {
                        fd = pfd[i].fd; pfd[i].fd = -1; goto done;
                    }
                }
                if (pfd[i].revents & (POLLERR|POLLHUP)) CLOSEFD(i);
            }
        } else if (r == 0) {
        handle_timeouts:;
            struct timespec now_ts;
            clock_gettime(CLOCK_MONOTONIC, &now_ts);
            for (size_t i = 0; i < 6; ++i) {
                if (pfd[i].fd >= 0 && connect_timed_out(&spawn_ts[i], &now_ts)) CLOSEFD(i);
            }
        } else {
            if (errno == EINTR) goto handle_timeouts;
            assert(fd == -1);
            goto done;
        }
        if (pfd[0].fd == -1 || pfd[1].fd == -1 || pfd[2].fd == -1
            || pfd[3].fd == -1 || pfd[4].fd == -1 || pfd[5].fd == -1) {
        jumpstart:;
            int tfd = queue_connect(&addr, &ctx, spawn_ts, pfd);
            if (tfd >= 0) {
                fd = tfd;
                break;
            } else if (tfd == -2 && pfd[0].fd == -1 && pfd[1].fd == -1 && pfd[2].fd == -1
                       && pfd[3].fd == -1 && pfd[4].fd == -1 && pfd[5].fd == -1) {
                // Failed to connect to all addresses.
                break;
            }
        }
    }
done:
    for (size_t i = 0; i < 6; ++i) CLOSEFD(i);
    if (fd == -1) {
        ctx.errc = EC_CONN_REFUSED;
        goto err1;
    }
    int flags = 1;
    if (UNLIKELY(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof flags) < 0)) {
        dprintf(2, "failed to set TCP_NODELAY on remote socket\n");
    }
    freeaddrinfo(ctx.remote);
    if (g_logging) {
        int af = SOCKADDR_UNION_AF(&t->client.addr);
        void *ipdata = SOCKADDR_UNION_ADDRESS(&t->client.addr);
        inet_ntop(af, ipdata, clientname, sizeof clientname);
        dolog("client[%d] %s: connected to %s:%d\n", t->client.fd, clientname, ctx.namebuf, ctx.port);
    }
    if (LIKELY(send_error(&t->client, t->client.fd, EC_SUCCESS) >= 0)) {
        copyloop(t->client.fd, fd, clientname, &ctx);
    }
    close(fd);
 out0:
    clientthread_cleanup(t);
    return NULL;
 err1:
    freeaddrinfo(ctx.remote);
 err0:
    send_error(&t->client, t->client.fd, ctx.errc);
    goto out0;
}
#undef CLOSEFD

static int usage(void) {
    dprintf(2,
            "muonsocks SOCKS 4 and 5 Server\n"
            "------------------------\n"
            "usage: muonsocks -1 -i listenip -p port -U user -P password -b bindaddr\n"
            "all arguments are optional.\n"
            "by default listenip is 0.0.0.0 and port 1080; -i may be given more than once.\n\n"
            "option -v enables logging to stderr\n"
            "option -4 or -6 disables ipv6 or ipv4 respectively\n"
            "option -u <user> runs muonsocks as the given user\n"
            "option -C <dir> makes muonsocks chroot to the specified dir\n"
            "option -b specifies which ip outgoing connections are bound to\n"
            "option -1 activates auth_once mode: once a specific ip address\n"
            "authed successfully with user/pass, it is added to a whitelist\n"
            "and may use the proxy without auth.\n"
            "this is handy for programs like firefox that don't support\n"
            "user/pass auth. for it to work you'd basically make one connection\n"
            "with another program that supports it, and then you can use firefox too.\n"
    );
    return 1;
}

/* prevent username and password from showing up in top. */
static void zero_arg(char *s) {
    memset(s, 0, strlen(s));
}

static void ban_dest_add(int af, const char *addr, uint32_t mask)
{
    struct in_addr ip4 = {0};
    struct in6_addr ip6 = {0};

    if (af != AF_INET && af != AF_INET6) return;
    if (inet_pton(af, addr, af == AF_INET ? (char *)&ip4 : (char *)&ip6) != 1)
        return;
    ban_dest = reallocarray(ban_dest, nban_dest + 1, sizeof(struct bandst));
    if (!ban_dest) {
        perror("reallocarray");
        exit(EXIT_FAILURE);
    }
    ban_dest[nban_dest++] = (struct bandst){ .fam = af, .addr4 = ip4, .addr6 = ip6, .mask = mask };
}

int main(int argc, char** argv) {
    bind_addr.v4.sin_family = AF_UNSPEC;
    size_t nsrvrs = 0;
    struct server *srvrs = NULL;
    int ch;
    unsigned short port = 1080;

    while ((ch = getopt(argc, argv, ":146vb:u:C:U:P:i:p:")) != -1) {
        switch (ch) {
        case '1':
            use_auth_ips = true;
            break;
        case '4':
            allow_ipv6 = false;
            break;
        case '6':
            allow_ipv4 = false;
            break;
        case 'v':
            g_logging = true;
            break;
        case 'b':
            resolve_sa(optarg, 0, &bind_addr);
            break;
        case 'u':
            if (g_user_id) free(g_user_id);
            g_user_id = strdup(optarg);
            break;
        case 'C':
            if (g_chroot) free(g_chroot);
            g_chroot = strdup(optarg);
            break;
        case 'U':
            if (g_auth_user) free(g_auth_user);
            g_auth_user = strdup(optarg);
            zero_arg(optarg);
            break;
        case 'P':
            if (g_auth_pass) free(g_auth_pass);
            g_auth_pass = strdup(optarg);
            zero_arg(optarg);
            break;
        case 'i':
            srvrs = reallocarray(srvrs, nsrvrs + 1, sizeof(struct server));
            if (!srvrs) {
                perror("reallocarray");
                return 1;
            }
            srvrs[nsrvrs++].listenip = optarg;
            break;
        case 'p': {
            int p = atoi(optarg);
            if (p < 0) {
                dprintf(2, "-p PORT can't be negative\n");
                return 1;
            }
            port = (unsigned short)p;
            break;
        }
        case ':':
            dprintf(2, "error: option -%c requires an operand\n", optopt);
            /* fall through */
        case '?':
            return usage();
        }
    }
    if (nsrvrs == 0) {
        srvrs = reallocarray(srvrs, nsrvrs + 1, sizeof(struct server));
        if (!srvrs) {
            perror("reallocarray");
            return 1;
        }
        srvrs[nsrvrs++].listenip = "0.0.0.0";
    }
    if ((g_auth_user && !g_auth_pass) || (!g_auth_user && g_auth_pass)) {
        dprintf(2, "error: user and pass must be used together\n");
        return 1;
    }
    if (use_auth_ips && !g_auth_pass) {
        dprintf(2, "error: auth-once option must be used together with user/pass\n");
        return 1;
    }
    if (!allow_ipv6 && !allow_ipv4) {
        dprintf(2, "error: -4 and -6 options cannot be used together\n");
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);

    ban_dest_add(AF_INET, "127.0.0.0", 8);
    ban_dest_add(AF_INET6, "::1", 128);

    for (size_t i = 0; i < nsrvrs; ++i) {
        if (server_setup(&srvrs[i], port)) {
            perror("server_setup");
            return 1;
        }
    }

    /* This is tricky -- we *must* use a name that will not be in hosts,
     * otherwise, at least with eglibc, the resolve and NSS libraries will not
     * be properly loaded.  The '.invalid' label is RFC-guaranteed to never
     * be installed into the root zone, so we use that to avoid harassing
     * DNS servers at start.
     */
    (void) gethostbyname("fail.invalid");

    // Only initialized to silence spurious warnings.
    uid_t muonsocks_uid = getuid();
    gid_t muonsocks_gid = getgid();
    if (g_user_id) {
        if (nk_uidgidbyname(g_user_id, &muonsocks_uid, &muonsocks_gid)) {
            dprintf(2, "invalid user '%s' specified\n", g_user_id);
            return 1;
        }
    }
    if (g_chroot)
        nk_set_chroot(g_chroot);
    if (g_user_id)
        nk_set_uidgid(muonsocks_uid, muonsocks_gid, NULL, 0);

    struct pollfd *fds = malloc(nsrvrs * sizeof(struct pollfd));
    for (size_t i = 0; i < nsrvrs; ++i) {
        fds[i] = (struct pollfd){ .fd = srvrs[i].fd, .events = POLLIN };
    }
    if (UNLIKELY(pthread_mutex_init(&auth_ips_mtx, NULL))) {
        perror("pthread_mutex_init");
        return 1;
    }

    pthread_attr_t attr;
    if (pthread_attr_init(&attr)) abort();
    if (pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE)) {
        perror("pthread_attr_setstacksize");
        return 1;
    }

    for (;;) {
        bool printed_err = false;
        gc_threads();
    poll_again:;
        int nr = poll(fds, nsrvrs, -1);
        if (UNLIKELY(nr == 0)) continue;
        if (UNLIKELY(nr == -1)) {
            if (errno == EINTR) goto poll_again;
            if (errno == ENOMEM) {
                delay10ms();
                goto poll_again;
            }
            perror("poll");
            break;
        }
        for (size_t i = 0; i < nsrvrs; ++i) {
            if (fds[i].revents & POLLIN) {
                for (;;) {
                    gc_threads();

                    // This optimizes for the common break case at the cost of
                    // dropping a connection on malloc failure below.
                    struct client c;
                    int r = server_waitclient(&srvrs[i], &c);
                    if (r) {
                        if (r == -1) break;
                        goto oom0;
                    }

                    struct thread *ct;
                    if (g_freelist) {
                        ct = g_freelist;
                        g_freelist = ct->gc_next;
                    } else {
                        ct = grow_struct_thread();
                        if (UNLIKELY(!ct)) goto oom1;
                    }

                    ct->client = c;
                    r = pthread_create(&ct->pt, &attr, clientthread, ct);
                    if (UNLIKELY(r)) {
                        free_struct_thread(ct);
oom1:
                        close(c.fd);
oom0:
                        if (!printed_err) {
                            printed_err = true;
                            dprintf(2, "FD limit or OOM: connection dropped\n");
                        }
                        delay10ms();
                        continue;
                    }
                }
            }
        }
    }
    pthread_attr_destroy(&attr);
}
