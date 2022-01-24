/*
   muonsocks - multithreaded, small, efficient SOCKS5 server.

   Copyright (C) 2017 rofl0r.
   Copyright 2020-2022 Nicholas J. Kain

   This program is derived from rofl0r's excellent microsocks:

   This is the successor of "rocksocks5", and it was written with
   different goals in mind:

   - prefer usage of standard libc functions over homegrown ones
   - no artificial limits
   - do not aim for minimal binary size, but for minimal source code size,
     and maximal readability, reusability, and extensibility.

   as a result of that, ipv4, dns, and ipv6 is supported out of the box
   and can use the same code, while rocksocks5 has several compile time
   defines to bring down the size of the resulting binary to extreme values
   like 10 KB static linked when only ipv4 support is enabled.

   still, if optimized for size, *this* program when static linked against musl
   libc is not even 50 KB. that's easily usable even on the cheapest routers.

*/

#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
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
#include <memory>
#include <vector>
#include <algorithm>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <charconv>
#include <utility>
#include "nk/scopeguard.hpp"
#include "sockunion.h"
extern "C" {
#include "nk/privs.h"
}

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#ifdef PTHREAD_STACK_MIN
#define THREAD_STACK_SIZE MAX(8*1024, PTHREAD_STACK_MIN)
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

#define BUF_SIZE 4096
#define MAX_BATCH 32

struct client {
    union sockaddr_union addr;
    int fd;
    int socksver;
};

struct server {
    server(const char *lip) : listenip(lip) {}
    const char *listenip;
    int fd;
};

struct thread {
    pthread_t pt;
    struct client client;
    std::atomic<bool> done;
};

static bool allow_ipv4 = true;
static bool allow_ipv6 = true;
static const char* g_user_id;
static const char* g_chroot;
static const char* auth_user;
static const char* auth_pass;
static bool use_auth_ips = false;
static std::vector<sockaddr_union *> auth_ips;
static std::shared_mutex auth_ips_mtx;
static union sockaddr_union bind_addr;

enum authmethod : char {
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

#ifndef CONFIG_LOG
#define CONFIG_LOG 1
#endif
#if CONFIG_LOG
/* we log to stderr because it's not using line buffering, i.e. malloc which would need
   locking when called from different threads. for the same reason we use dprintf,
   which writes directly to an fd. */
#define dolog(...) dprintf(2, __VA_ARGS__)
#else
static void dolog(const char* fmt, ...) { }
#endif

static int family_choose(struct addrinfo *remote, union sockaddr_union *bind_addr) {
    int family = SOCKADDR_UNION_AF(bind_addr);
    return family == AF_UNSPEC ? remote->ai_family : family;
}

static struct addrinfo* addr_choose(struct addrinfo *list, union sockaddr_union *bind_addr) {
    int family = SOCKADDR_UNION_AF(bind_addr);
    if (family == AF_UNSPEC) return list;
    struct addrinfo *p;
    for (p = list; p; p = p->ai_next) {
        if (p->ai_family == family) return p;
    }
    dprintf(2, "warning: address family mismatch\n");
    return list;
}

static int resolve(const char *host, unsigned short port, int fam, struct addrinfo** addr) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = fam;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    char port_buf[8];
    auto r = std::to_chars(port_buf, port_buf + sizeof port_buf, port);
    if (r.ec != std::errc()) return EAI_SYSTEM;
    *r.ptr = 0;
    return getaddrinfo(host, port_buf, &hints, addr);
}

static int resolve_sa(const char *host, unsigned short port, union sockaddr_union *res) {
    struct addrinfo *ainfo = 0;
    int ret;
    SOCKADDR_UNION_AF(res) = AF_UNSPEC;
    if ((ret = resolve(host, port, AF_UNSPEC, &ainfo))) return ret;
    SCOPE_EXIT { freeaddrinfo(ainfo); };
    memcpy(res, ainfo->ai_addr, ainfo->ai_addrlen);
    return 0;
}

static int bindtoip(int fd, union sockaddr_union *bindaddr) {
    socklen_t sz = SOCKADDR_UNION_LENGTH(bindaddr);
    if (!sz) return 0;
    return bind(fd, (struct sockaddr*) bindaddr, sz);
}

static int server_waitclient(struct server *server, struct client* client) {
    socklen_t clen = sizeof client->addr;
    client->fd = accept(server->fd, reinterpret_cast<sockaddr *>(&client->addr), &clen);
    if (client->fd == -1) {
        usleep(1000); // Prevent busy-spin when fd limit is reached
        return -1;
    }
    int flags = 1;
    if (setsockopt(client->fd, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof flags) < 0) {
        dprintf(2, "failed to set TCP_NODELAY on client socket\n");
    }
    return 0;
}

static int server_setup(struct server *server, unsigned short port) {
    struct addrinfo *ainfo = nullptr;
    if (resolve(server->listenip, port, AF_UNSPEC, &ainfo)) return -1;
    SCOPE_EXIT { freeaddrinfo(ainfo); };
    int listenfd = -1;
    for (auto p = ainfo; p; p = p->ai_next) {
        if ((listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
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
        int flags = fcntl(listenfd, F_GETFL);
        if (flags < 0) {
            close(listenfd);
            listenfd = -1;
            continue;
        }
        if (fcntl(listenfd, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(listenfd);
            listenfd = -1;
            continue;
        }
        break;
    }
    if (listenfd < 0) return -2;
    if (listen(listenfd, SOMAXCONN) < 0) {
        close(listenfd);
        return -3;
    }
    server->fd = listenfd;
    return 0;
}

static int is_authed(union sockaddr_union *client, union sockaddr_union *authedip) {
    int af = SOCKADDR_UNION_AF(authedip);
    if (af == SOCKADDR_UNION_AF(client)) {
        size_t cmpbytes = af == AF_INET ? 4 : 16;
        auto cmp1 = SOCKADDR_UNION_ADDRESS(client);
        auto cmp2 = SOCKADDR_UNION_ADDRESS(authedip);
        if (!memcmp(cmp1, cmp2, cmpbytes)) return 1;
    }
    return 0;
}

static int is_in_authed_list(union sockaddr_union *caddr) {
    for (auto i: auth_ips) {
        if (is_authed(caddr, i)) return 1;
    }
    return 0;
}

static void add_auth_ip(union sockaddr_union *caddr) {
    auth_ips.push_back(caddr);
}

static int send_auth_response(int fd, char version, enum authmethod method) {
    char buf[2] = { version, method };
    ssize_t r = write(fd, buf, sizeof buf);
    return r == sizeof buf ? r : -1;
}

static int send_error(const client &c, int fd, enum errorcode ec) {
    if (c.socksver == 5) {
        /* position 4 contains ATYP, the address type, which is the same as used in the connect
           request. we're lazy and return always IPV4 address type in errors. */
        char buf[10] = { 5, ec, 0, 1 /*AT_IPV4*/, 0,0,0,0, 0,0 };
        ssize_t r = write(fd, buf, sizeof buf);
        return r == sizeof buf ? r : -1;
    } else if (c.socksver == 4) {
        char buf[8] = { 0, ec == 0 ? char(0x5a) : char(0x5b), 0,0, 0,0,0,0 };
        ssize_t r = write(fd, buf, sizeof buf);
        return r == sizeof buf ? r : -1;
    } else {
        return -1;
    }
}

static void copyloop(const client &c, int fd1, int fd2, char *buf) {
    struct pollfd fds[2] = {
        { fd1, POLLIN, 0},
        { fd2, POLLIN, 0},
    };

    for (;;) {
        /* inactive connections are reaped after 15 min to free resources.
           usually programs send keep-alive packets so this should only happen
           when a connection is really unused. */
        switch (poll(fds, 2, 60*15*1000)) {
        default: break;
        case 0:
                 send_error(c, fd1, EC_TTL_EXPIRED);
                 return;
        case -1:
                 if (errno == EINTR || errno == EAGAIN) continue;
                 else perror("poll");
                 return;
        }
        int infd = (fds[0].revents & POLLIN) ? fd1 : fd2;
        int outfd = infd == fd2 ? fd1 : fd2;
        ssize_t sent, n;
        int cycles = MAX_BATCH;
read_retry:
        sent = 0;
        if (--cycles <= 0) continue; // Don't let one channel monopolize.
        n = recv(infd, buf, BUF_SIZE, MSG_DONTWAIT);
        if (n == 0) return;
        if (n < 0) {
            switch (errno) {
            case EINTR: goto read_retry;
            case EAGAIN: continue;
            default: return;
            }
        }
        while (sent < n) {
            ssize_t m = write(outfd, buf+sent, n-sent);
            if (m < 0) {
                if (errno == EINTR) continue;
                return;
            }
            sent += m;
        }
        goto read_retry;
    }
}

static bool extend_cbuf(const thread *t, char *buf, size_t &buflen)
{
    for (;;) {
        auto n = read(t->client.fd, buf + buflen, BUF_SIZE - buflen);
        if (n == 0) {
            return false;
        } else if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        buflen += n;
        return true;
    }
}

#define EXTEND_BUF() do { if (!extend_cbuf(t, buf, buflen)) return nullptr; } while (0)
#define RESET_BUF() do { buflen = 0; } while (0)

static enum errorcode errno_to_sockscode()
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

static void* clientthread(void *data) {
    auto t = static_cast<thread *>(data);
    char buf[BUF_SIZE];
    char namebuf[256];
    size_t buflen = 0;
    enum authmethod am = AM_INVALID;
    int fam = AF_UNSPEC;
    unsigned short port;

    SCOPE_EXIT {
        close(t->client.fd);
        t->done = true;
    };
    EXTEND_BUF();

    t->client.socksver = buf[0];
    if (t->client.socksver == 5) {
        while (buflen < 2) { EXTEND_BUF(); }
        size_t n_methods = buf[1];
        while (buflen < 2 + n_methods) { EXTEND_BUF(); }
        for (size_t i = 0; i < n_methods; ++i) {
            if (buf[2 + i] == AM_NO_AUTH) {
                if (!auth_user) {
                    am = AM_NO_AUTH;
                    break;
                } else if (use_auth_ips) {
                    bool authed = 0;
                    {
                        std::shared_lock mtx(auth_ips_mtx);
                        authed = is_in_authed_list(&t->client.addr);
                    }
                    if (authed) {
                        am = AM_NO_AUTH;
                        break;
                    }
                }
            } else if (buf[2 + i] == AM_USERNAME) {
                if (auth_user) {
                    am = AM_USERNAME;
                    break;
                }
            }
        }
        if (am == AM_INVALID) return nullptr;

        RESET_BUF();
        if (send_auth_response(t->client.fd, 5, am) < 0) return nullptr;
        if (am == AM_USERNAME) {
            while (buflen < 5) { EXTEND_BUF(); }
            if (buf[0] != 1) return nullptr;
            unsigned ulen, plen;
            ulen = buf[1];
            while (buflen < 2 + ulen + 2) { EXTEND_BUF(); }
            plen = buf[2 + ulen];
            while (buflen < 2 + ulen + 1 + plen) { EXTEND_BUF(); }
            char user[256], pass[256];
            memcpy(user, buf + 2, ulen);
            memcpy(pass, buf + 2 + ulen + 1, plen);
            user[ulen] = 0;
            pass[plen] = 0;
            bool allow = !strcmp(user, auth_user) && !strcmp(pass, auth_pass);
            if (!allow) return nullptr;
            if (use_auth_ips) {
                std::unique_lock mtx(auth_ips_mtx);
                if (!is_in_authed_list(&t->client.addr))
                    add_auth_ip(&t->client.addr);
            }
            if (send_auth_response(t->client.fd, 1, am) < 0) return nullptr;
            RESET_BUF();
        }

        // Now we're done with the authentication negotiations.
        while (buflen < 5) { EXTEND_BUF(); }
        if (buf[0] != 5) {
            send_error(t->client, t->client.fd, EC_GENERAL_FAILURE);
            return nullptr;
        }
        if (buf[1] != 1) {
            send_error(t->client, t->client.fd, EC_COMMAND_NOT_SUPPORTED);
            return nullptr;
        }
        if (buf[2] != 0) {
            send_error(t->client, t->client.fd, EC_GENERAL_FAILURE);
            return nullptr;
        }

        size_t minlen;
        if (buf[3] == 3) {
            size_t l = buf[4];
            minlen = 4 + 1 + l + 2;
            while (buflen < minlen) { EXTEND_BUF(); }
            memcpy(namebuf, buf + 4 + 1, l);
            namebuf[l] = 0;
        } else {
            int af;
            if (buf[3] == 1) {
                af = AF_INET;
                minlen = 4 + 4 + 2;
            } else if (buf[3] == 4) {
                af = AF_INET6;
                minlen = 4 + 16 + 2;
            } else {
                send_error(t->client, t->client.fd, EC_ADDRESSTYPE_NOT_SUPPORTED);
                return nullptr;
            }
            while (buflen < minlen) { EXTEND_BUF(); }
            if (namebuf != inet_ntop(af, buf + 4, namebuf, sizeof namebuf)) {
                send_error(t->client, t->client.fd, EC_GENERAL_FAILURE);
                return nullptr;
            }
        }
        memcpy(&port, buf + minlen - 2, 2);
        port = ntohs(port);
        if (!allow_ipv4) fam = AF_INET6;
        if (!allow_ipv6) fam = AF_INET;
    } else if (t->client.socksver == 4) {
        if (auth_pass) {
            send_error(t->client, t->client.fd, EC_GENERAL_FAILURE);
            return nullptr;
        }
        if (!allow_ipv4) {
            send_error(t->client, t->client.fd, EC_ADDRESSTYPE_NOT_SUPPORTED);
            return nullptr;
        }

        while (buflen < 9) { EXTEND_BUF(); }
        if (buf[0] != 4) {
            send_error(t->client, t->client.fd, EC_GENERAL_FAILURE);
            return nullptr;
        }
        if (buf[1] != 1) {
            send_error(t->client, t->client.fd, EC_COMMAND_NOT_SUPPORTED);
            return nullptr;
        }
        memcpy(&port, buf + 2, 2);
        port = ntohs(port);

        bool is_dns = false;
        if (buf[4] == 0 && buf[5] == 0 && buf[6] == 0 && buf[7] != 0) {
            is_dns = true;
        } else {
            if (namebuf != inet_ntop(AF_INET, buf + 4, namebuf, sizeof namebuf)) {
                send_error(t->client, t->client.fd, EC_GENERAL_FAILURE);
                return nullptr;
            }
        }
        size_t i = 8;
        for (;;++i) {
            // Here we just skip the userid for now
            if (i > BUF_SIZE / 2) {
                send_error(t->client, t->client.fd, EC_GENERAL_FAILURE);
                return nullptr;
            }
            while (buflen < i + 1) { EXTEND_BUF(); }
            if (buf[i] == 0) { ++i; break; }
        }
        if (is_dns) {
            size_t buf_start = i;
            for (;;++i) {
                if (i - buf_start > sizeof namebuf - 1) {
                    send_error(t->client, t->client.fd, EC_GENERAL_FAILURE);
                    return nullptr;
                }
                while (buflen < i + 1) { EXTEND_BUF(); }
                if (buf[i] == 0) {
                    memcpy(namebuf, buf + buf_start, i - buf_start);
                    namebuf[i - buf_start] = 0;
                    break;
                }
            }
        }
        fam = AF_INET;
    } else {
        return nullptr;
    }
    /* there's no suitable errorcode in rfc1928 for dns lookup failure */
    struct addrinfo* remote;
    if (resolve(namebuf, port, fam, &remote)) {
        send_error(t->client, t->client.fd, EC_GENERAL_FAILURE);
        return nullptr;
    }
    SCOPE_EXIT { freeaddrinfo(remote); };
    if (!allow_ipv6 && remote->ai_addr->sa_family == AF_INET6) {
        send_error(t->client, t->client.fd, EC_ADDRESSTYPE_NOT_SUPPORTED);
        return nullptr;
    }
    if (!allow_ipv4 && remote->ai_addr->sa_family == AF_INET) {
        send_error(t->client, t->client.fd, EC_ADDRESSTYPE_NOT_SUPPORTED);
        return nullptr;
    }
    int family = family_choose(remote, &bind_addr);
    int fd = socket(family, SOCK_STREAM, 0);
    if (fd == -1) {
        send_error(t->client, t->client.fd, errno_to_sockscode());
        return nullptr;
    }
    SCOPE_EXIT { close(fd); };
    int flags = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof flags) < 0) {
        dprintf(2, "failed to set TCP_NODELAY on remote socket\n");
    }
    if (SOCKADDR_UNION_AF(&bind_addr) != AF_UNSPEC && bindtoip(fd, &bind_addr) == -1) {
        send_error(t->client, t->client.fd, errno_to_sockscode());
        return nullptr;
    }
    struct addrinfo *addr = addr_choose(remote, &bind_addr);
    if (connect(fd, addr->ai_addr, addr->ai_addrlen) == -1) {
        send_error(t->client, t->client.fd, errno_to_sockscode());
        return nullptr;
    }

    if (CONFIG_LOG) {
        char clientname[256];
        int af = SOCKADDR_UNION_AF(&t->client.addr);
        void *ipdata = SOCKADDR_UNION_ADDRESS(&t->client.addr);
        inet_ntop(af, ipdata, clientname, sizeof clientname);
        dolog("client[%d] %s: connected to %s:%d\n", t->client.fd, clientname, namebuf, port);
    }
    if (send_error(t->client, t->client.fd, EC_SUCCESS) < 0) return nullptr;
    RESET_BUF();
    copyloop(t->client, t->client.fd, fd, buf);
    return nullptr;
}

static void collect(std::vector<std::unique_ptr<thread>> &threads) {
threads.erase(std::remove_if(threads.begin(), threads.end(),
                             [&](std::unique_ptr<thread> &t) -> bool {
                                if (t->done) {
                                    pthread_join(t->pt, 0);
                                    return true;
                                }
                                return false;
                             }), threads.end());
}

static int usage(void) {
    dprintf(2,
            "muonsocks SOCKS5 Server\n"
            "------------------------\n"
            "usage: muonsocks -1 -i listenip -p port -u user -P password -b bindaddr\n"
            "all arguments are optional.\n"
            "by default listenip is 0.0.0.0 and port 1080.\n\n"
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

int main(int argc, char** argv) {
    bind_addr.v4.sin_family = AF_UNSPEC;
    std::vector<struct server> servers;
    std::vector<std::unique_ptr<thread>> threads;
    int ch;
    unsigned port = 1080;
    while ((ch = getopt(argc, argv, ":146b:u:C:U:P:i:p:")) != -1) {
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
        case 'b':
            resolve_sa(optarg, 0, &bind_addr);
            break;
        case 'u':
            g_user_id = strdup(optarg);
            break;
        case 'C':
            g_chroot = strdup(optarg);
            break;
        case 'U':
            auth_user = strdup(optarg);
            zero_arg(optarg);
            break;
        case 'P':
            auth_pass = strdup(optarg);
            zero_arg(optarg);
            break;
        case 'i':
            servers.emplace_back(optarg);
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case ':':
            dprintf(2, "error: option -%c requires an operand\n", optopt);
            /* fall through */
        case '?':
            return usage();
        }
    }
    if (servers.empty()) servers.emplace_back("0.0.0.0");
    if ((auth_user && !auth_pass) || (!auth_user && auth_pass)) {
        dprintf(2, "error: user and pass must be used together\n");
        return 1;
    }
    if (use_auth_ips && !auth_pass) {
        dprintf(2, "error: auth-once option must be used together with user/pass\n");
        return 1;
    }
    if (!allow_ipv6 && !allow_ipv4) {
        dprintf(2, "error: -4 and -6 options cannot be used together\n");
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);

    for (auto &i: servers) {
        if (server_setup(&i, port)) {
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

    uid_t nsocks_uid;
    gid_t nsocks_gid;
    if (g_user_id) {
        if (nk_uidgidbyname(g_user_id, &nsocks_uid, &nsocks_gid)) {
            dprintf(2, "invalid user '%s' specified\n", g_user_id);
            return 1;
        }
    }
    if (g_chroot)
        nk_set_chroot(g_chroot);
    if (g_user_id)
        nk_set_uidgid(nsocks_uid, nsocks_gid, NULL, 0);

    auto fds = std::make_unique<struct pollfd[]>(servers.size());
    for (size_t i = 0, iend = servers.size(); i < iend; ++i) {
        fds[i] = { servers[i].fd, POLLIN, 0 };
    }

    for (;;) {
        collect(threads);
poll_again:
        switch (poll(fds.get(), servers.size(), -1)) {
        default: break;
        case -1: if (errno == EINTR || errno == EAGAIN) continue;
                 else perror("poll");
        case 0:  goto poll_again;
        }
        for (size_t i = 0, iend = servers.size(); i < iend; ++i) {
            if (fds[i].revents & POLLIN) {
                for (;;) {
                    struct client c;
                    if (server_waitclient(&servers[i], &c))
                        break;
                    threads.emplace_back(std::make_unique<thread>());
                    auto ct = threads.back().get();
                    ct->done = false;
                    ct->client = c;
                    pthread_attr_t *a = 0, attr;
                    if (pthread_attr_init(&attr) == 0) {
                        a = &attr;
                        pthread_attr_setstacksize(a, THREAD_STACK_SIZE);
                    }
                    if (pthread_create(&ct->pt, a, clientthread, ct) != 0)
                        dprintf(2, "pthread_create failed. OOM?\n");
                    if (a) pthread_attr_destroy(&attr);
                }
            }
        }
    }
}
