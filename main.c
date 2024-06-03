/*
   muonsocks - multithreaded, small, efficient SOCKS(5|4a) server.

   Copyright (C) 2017 rofl0r.
   Copyright 2020-2024 Nicholas J. Kain

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

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#if defined(__GNUC__) || defined(__clang__)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define LIKELY(x) __builtin_expect(!!(x), 1)
#else
#define UNLIKELY(x) (x)
#define LIKELY(x) (x)
#endif

#ifdef PTHREAD_STACK_MIN
#define THREAD_STACK_SIZE MAX(16*1024, PTHREAD_STACK_MIN)
#else
#define THREAD_STACK_SIZE 64*1024
#endif

#if defined(__APPLE__)
#undef THREAD_STACK_SIZE
#define THREAD_STACK_SIZE 64*1024
#elif defined(__GLIBC__) || defined(__FreeBSD__)
#undef THREAD_STACK_SIZE
#define THREAD_STACK_SIZE 32*1024
#endif

#if (defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFlyBSD__))
#define USE_ACCEPT4
#endif

// BUF_SIZE is set to a multiple of a typical 1500 MTU
// minus options-free IPv6 (40) and TCP (20) headers
#if THREAD_STACK_SIZE >= 48 * 1024
#define BUF_SIZE 31680
#define MAX_BATCH 4
#elif THREAD_STACK_SIZE >= 32 * 1024
#define BUF_SIZE 17280
#define MAX_BATCH 7
#else
#define BUF_SIZE 8640
#define MAX_BATCH 15
#endif


// Number of unused struct thread to keep alloced for reuse.
#define MAX_FREELIST 50

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
static int s6_notify_fd = 3;
static bool allow_ipv4 = true;
static bool allow_ipv6 = true;
static bool s6_notify_enable = false;
static bool use_auth_ips = false;
static bool g_logging = false;
static size_t nauth_ips;
static size_t nban_dest;
static union sockaddr_union *auth_ips;
static struct bandst *ban_dest;
static pthread_mutex_t auth_ips_mtx;
static union sockaddr_union bind_addr;

static _Atomic (struct thread *) g_gc_list;
// These are only ever accessed on the main listening thread.
static struct thread *g_freelist;
static size_t g_nfreelist;

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

static int family_choose(struct addrinfo *remote, union sockaddr_union *addr) {
    int family = SOCKADDR_UNION_AF(addr);
    return family == AF_UNSPEC ? remote->ai_family : family;
}

static struct addrinfo* addr_choose(struct addrinfo *list, union sockaddr_union *addr) {
    int family = SOCKADDR_UNION_AF(addr);
    if (family == AF_UNSPEC) return list;
    struct addrinfo *p;
    for (p = list; p; p = p->ai_next) {
        if (p->ai_family == family) return p;
    }
    dprintf(2, "warning: address family mismatch\n");
    return list;
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

static void free_struct_thread(struct thread *t)
{
    if (g_nfreelist < MAX_FREELIST) {
        ++g_nfreelist;
        t->gc_next = g_freelist;
        g_freelist = t;
    } else {
        free(t);
    }
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
#ifdef USE_ACCEPT4
    client->fd = accept4(server->fd, (struct sockaddr *)&client->addr, &clen, SOCK_CLOEXEC);
#else
    client->fd = accept(server->fd, (struct sockaddr *)&client->addr, &clen);
#endif
    if (client->fd == -1) {
        switch (errno) {
#ifdef __linux__
        case ENETDOWN:
        case EPROTO:
        case ENOPROTOOPT:
        case EHOSTDOWN:
        case ENONET:
        case EHOSTUNREACH:
        case EOPNOTSUPP:
        case ENETUNREACH:
#endif
        case EINTR: goto retry;
        case EMFILE:
        case ENFILE:
        case ENOBUFS:
        case ENOMEM:
            // Resource limit reached errors.
            return -2;
        default:
            return -1;
        }
    }
    int flags = 1;
#ifndef USE_ACCEPT4
    flags = fcntl(client->fd, F_GETFL);
    if (fcntl(client->fd, F_SETFL, flags & ~O_NONBLOCK) == -1)
        dprintf(2, "failed to set O_NONBLOCK on client socket\n");
    if (fcntl(client->fd, F_SETFD, FD_CLOEXEC) == -1)
        dprintf(2, "failed to set CLOEXEC on client socket\n");
#endif
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
        if ((listenfd = socket(p->ai_family, p->ai_socktype|SOCK_CLOEXEC|SOCK_NONBLOCK, p->ai_protocol)) < 0)
            continue;
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
    for (;;) {
        ssize_t r = write(fd, buf, sizeof buf);
        if (r == -1 && errno == EINTR) continue;
        return r == sizeof buf ? r : -1;
    }
}

static int send_error(const struct client *c, int fd, enum errorcode ec) {
    struct sockaddr_storage srcaddr = { .ss_family = AF_INET }; // for non-EC_SUCCESS case
    if (ec == EC_SUCCESS) {
        socklen_t srcaddrlen = sizeof srcaddr;
        if (getsockname(fd, (struct sockaddr *)&srcaddr, &srcaddrlen) == -1) return -1;
    }
    char b[24];
    size_t blen;
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
    for (;;) {
        ssize_t r = write(fd, b, blen);
        if (r == -1 && errno == EINTR) continue;
        return r == (ssize_t)blen ? r : -1;
    }
}

struct socksctx {
    char namebuf[256];
    struct addrinfo *remote;
    int errc;
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

static void copyloop(int fd1, int fd2, const char *clientname, const struct socksctx *ctx) {
    char buf[BUF_SIZE];
    struct pollfd fds[2] = {
        { fd1, POLLIN, 0},
        { fd2, POLLIN, 0},
    };
    struct srstats sr = { 0 };

    for (;;) {
        /* inactive connections are reaped after 15 min to free resources.
           usually programs send keep-alive packets so this should only happen
           when a connection is really unused. */
        switch (poll(fds, 2, 60*15*1000)) {
        case -1:
                 if (errno == EINTR || errno == EAGAIN) continue;
                 else perror("poll");
                 // fall through
        case 0:
                 log_dc(fd1, clientname, ctx, &sr);
                 return;
        default: break;
        }
        int infd = (fds[0].revents & POLLIN) ? fd1 : fd2;
        int outfd = infd == fd2 ? fd1 : fd2;
        ssize_t sent, n;
        int cycles = MAX_BATCH;
read_retry:
        sent = 0;
        if (--cycles <= 0) continue; // Don't let one channel monopolize.
        n = recv(infd, buf, BUF_SIZE, MSG_DONTWAIT);
        if (n == 0) {
            log_dc(fd1, clientname, ctx, &sr);
            return;
        }
        if (n < 0) {
            switch (errno) {
            case EINTR: goto read_retry;
            case EAGAIN: continue;
            default:
                log_dc(fd1, clientname, ctx, &sr);
                return;
            }
        }
        assert(n >= 0);
        if (infd == fd1) sr.bsent += (size_t)n;
        else sr.brecv += (size_t)n;
        while (sent < n) {
            ssize_t m = write(outfd, buf+sent, (size_t)(n-sent));
            if (m < 0) {
                if (errno == EINTR) continue;
                log_dc(fd1, clientname, ctx, &sr);
                return;
            }
            sent += m;
        }
        goto read_retry;
    }
}

static bool extend_cbuf(const struct thread *t, char *buf, size_t *buflen)
{
    for (;;) {
        ssize_t n = read(t->client.fd, buf + *buflen, BUF_SIZE - *buflen);
        if (n == 0) {
            return false;
        } else if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        *buflen += (size_t)n;
        return true;
    }
}

#define EXTEND_BUF() do { if (!extend_cbuf(t, buf, &buflen)) return -1; } while (0)
#define RESET_BUF() do { buflen = 0; } while (0)

static enum errorcode errno_to_sockscode(void)
{
    switch (errno) {
    case ETIMEDOUT:
        return EC_TTL_EXPIRED;
    case EPROTOTYPE:
    case EPROTONOSUPPORT:
    case EAFNOSUPPORT:
        return EC_ADDRESSTYPE_NOT_SUPPORTED;
    case ECONNREFUSED:
        return EC_CONN_REFUSED;
    case ENETDOWN:
    case ENETUNREACH:
        return EC_NET_UNREACHABLE;
    case EHOSTUNREACH:
        return EC_HOST_UNREACHABLE;
    case EBADF:
    default:
        return EC_GENERAL_FAILURE;
    }
}

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
    for (;;) {
        t->gc_next = g_gc_list;
        if (atomic_compare_exchange_strong(&g_gc_list, &t->gc_next, t)) break;
    }
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

static void* clientthread(void *data) {
    struct thread *t = (struct thread *)data;
    struct socksctx ctx;
    char clientname[256] = { 0 };
    struct addrinfo *addr;

    ctx.errc = EC_GENERAL_FAILURE;
    int r = parse_socksreq(t, &ctx);
    if (LIKELY(r == 0)) {
    } else if (r == -1) {
        goto out0;
    } else if (r == -2) {
        goto err0;
    }

    if (UNLIKELY(!allow_ipv6 && ctx.remote->ai_addr->sa_family == AF_INET6)) {
        ctx.errc = EC_ADDRESSTYPE_NOT_SUPPORTED;
        goto err1;
    }
    if (UNLIKELY(!allow_ipv4 && ctx.remote->ai_addr->sa_family == AF_INET)) {
        ctx.errc = EC_ADDRESSTYPE_NOT_SUPPORTED;
        goto err1;
    }
    int family, fd, flags;
    family = family_choose(ctx.remote, &bind_addr);
    if (UNLIKELY(is_banned(family, ctx.remote))) {
        goto err1;
    }
    fd = socket(family, SOCK_STREAM|SOCK_CLOEXEC, 0);
    if (UNLIKELY(fd == -1)) {
        ctx.errc = errno_to_sockscode();
        goto err1;
    }
    flags = 1;
    if (UNLIKELY(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof flags) < 0)) {
        dprintf(2, "failed to set TCP_NODELAY on remote socket\n");
    }
    if (UNLIKELY(SOCKADDR_UNION_AF(&bind_addr) != AF_UNSPEC && bindtoip(fd, &bind_addr) == -1)) {
        ctx.errc = errno_to_sockscode();
        goto err2;
    }
    addr = addr_choose(ctx.remote, &bind_addr);
    if (UNLIKELY(connect(fd, addr->ai_addr, addr->ai_addrlen) == -1)) {
        ctx.errc = errno_to_sockscode();
        goto err2;
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
 err2:
    close(fd);
 err1:
    freeaddrinfo(ctx.remote);
 err0:
    send_error(&t->client, t->client.fd, ctx.errc);
    goto out0;
}

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
            "option -d <fdnum> specifies the s6 notification file descriptor\n"
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

    while ((ch = getopt(argc, argv, ":146vb:u:C:U:P:i:p:d:")) != -1) {
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
        case 'd':
            s6_notify_fd = atoi(optarg);
            s6_notify_enable = true;
            break;
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

    if (s6_notify_enable) {
        char buf = '\n';
        for (;;) {
            ssize_t r = write(s6_notify_fd, &buf, 1);
            if (r < 1) {
                if (r == -1 && errno == EINTR) continue;
                perror("s6_notify/write");
                return 1;
            }
            break;
        }
        close(s6_notify_fd);
    }

    for (;;) {
        bool printed_err = false;
        gc_threads();
        switch (poll(fds, nsrvrs, -1)) {
        default: break;
        case -1: if (errno == EINTR || errno == EAGAIN) continue;
                 else perror("poll");
        case 0:  continue;
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
                    if (g_nfreelist > 0) {
                        --g_nfreelist;
                        ct = g_freelist;
                        g_freelist = g_freelist->gc_next;
                    } else {
                        ct = malloc(sizeof(struct thread));
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
