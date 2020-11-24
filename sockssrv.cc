/*
   MicroSocks - multithreaded, small, efficient SOCKS5 server.

   Copyright (C) 2017 rofl0r.

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
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <vector>
#include <algorithm>
extern "C" {
#include "server.h"
#include "privs.h"
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

static bool allow_ipv4 = true;
static bool allow_ipv6 = true;
static const char* g_user_id;
static const char* g_chroot;
static const char* auth_user;
static const char* auth_pass;
static bool use_auth_ips = false;
static std::vector<sockaddr_union *> auth_ips;
static pthread_rwlock_t auth_ips_lock = PTHREAD_RWLOCK_INITIALIZER;
static const struct server* server;
static union sockaddr_union bind_addr;

enum socksstate {
	SS_1_CONNECTED,
	SS_2_NEED_AUTH, /* skipped if NO_AUTH method supported */
	SS_3_AUTHED,
};

enum authmethod {
	AM_NO_AUTH = 0,
	AM_GSSAPI = 1,
	AM_USERNAME = 2,
	AM_INVALID = 0xFF
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

struct thread {
	pthread_t pt;
	struct client client;
	enum socksstate state;
	volatile int  done;
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

static int connect_socks_target(unsigned char *buf, size_t n, struct client *client) {
	if(n < 5) return -EC_GENERAL_FAILURE;
	if(buf[0] != 5) return -EC_GENERAL_FAILURE;
	if(buf[1] != 1) return -EC_COMMAND_NOT_SUPPORTED; /* we support only CONNECT method */
	if(buf[2] != 0) return -EC_GENERAL_FAILURE; /* malformed packet */

	int af = AF_INET;
	size_t minlen = 4 + 4 + 2, l;
	char namebuf[256];
	struct addrinfo* remote;

	switch(buf[3]) {
		case 4: /* ipv6 */
			af = AF_INET6;
			minlen = 4 + 2 + 16;
			/* fall through */
		case 1: /* ipv4 */
			if(n < minlen) return -EC_GENERAL_FAILURE;
			if(namebuf != inet_ntop(af, buf+4, namebuf, sizeof namebuf))
				return -EC_GENERAL_FAILURE; /* malformed or too long addr */
			break;
		case 3: /* dns name */
			l = buf[4];
			minlen = 4 + 2 + l + 1;
			if(n < 4 + 2 + l + 1) return -EC_GENERAL_FAILURE;
			memcpy(namebuf, buf+4+1, l);
			namebuf[l] = 0;
			break;
		default:
			return -EC_ADDRESSTYPE_NOT_SUPPORTED;
	}
	unsigned short port;
	port = (buf[minlen-2] << 8) | buf[minlen-1];
	int fam = AF_UNSPEC;
	if (!allow_ipv4) fam = AF_INET6;
	if (!allow_ipv6) fam = AF_INET;
	/* there's no suitable errorcode in rfc1928 for dns lookup failure */
	if(resolve(namebuf, port, fam, &remote)) return -EC_GENERAL_FAILURE;
	if (!allow_ipv6 && remote->ai_addr->sa_family == AF_INET6) {
		freeaddrinfo(remote);
		return -EC_ADDRESSTYPE_NOT_SUPPORTED;
	}
	if (!allow_ipv4 && remote->ai_addr->sa_family == AF_INET) {
		freeaddrinfo(remote);
		return -EC_ADDRESSTYPE_NOT_SUPPORTED;
	}
	int fd = socket(remote->ai_addr->sa_family, SOCK_STREAM, 0);
	if(fd == -1) {
		eval_errno:
		if(fd != -1) close(fd);
		freeaddrinfo(remote);
		switch(errno) {
			case ETIMEDOUT:
				return -EC_TTL_EXPIRED;
			case EPROTOTYPE:
			case EPROTONOSUPPORT:
			case EAFNOSUPPORT:
				return -EC_ADDRESSTYPE_NOT_SUPPORTED;
			case ECONNREFUSED:
				return -EC_CONN_REFUSED;
			case ENETDOWN:
			case ENETUNREACH:
				return -EC_NET_UNREACHABLE;
			case EHOSTUNREACH:
				return -EC_HOST_UNREACHABLE;
			case EBADF:
			default:
			perror("socket/connect");
			return -EC_GENERAL_FAILURE;
		}
	}
	if(SOCKADDR_UNION_AF(&bind_addr) != AF_UNSPEC && bindtoip(fd, &bind_addr) == -1)
		goto eval_errno;
	if(connect(fd, remote->ai_addr, remote->ai_addrlen) == -1)
		goto eval_errno;

	freeaddrinfo(remote);
	if(CONFIG_LOG) {
		char clientname[256];
		af = SOCKADDR_UNION_AF(&client->addr);
		void *ipdata = SOCKADDR_UNION_ADDRESS(&client->addr);
		inet_ntop(af, ipdata, clientname, sizeof clientname);
		dolog("client[%d] %s: connected to %s:%d\n", client->fd, clientname, namebuf, port);
	}
	return fd;
}

static int is_authed(union sockaddr_union *client, union sockaddr_union *authedip) {
	int af = SOCKADDR_UNION_AF(authedip);
	if(af == SOCKADDR_UNION_AF(client)) {
		size_t cmpbytes = af == AF_INET ? 4 : 16;
		void *cmp1 = SOCKADDR_UNION_ADDRESS(client);
		void *cmp2 = SOCKADDR_UNION_ADDRESS(authedip);
		if(!memcmp(cmp1, cmp2, cmpbytes)) return 1;
	}
	return 0;
}

static int is_in_authed_list(union sockaddr_union *caddr) {
	size_t i;
	for (auto i: auth_ips) {
		if(is_authed(caddr, i)) return 1;
	}
	return 0;
}

static void add_auth_ip(union sockaddr_union *caddr) {
	auth_ips.push_back(caddr);
}

static enum authmethod check_auth_method(unsigned char *buf, size_t n, struct client*client) {
	if(buf[0] != 5) return AM_INVALID;
	size_t idx = 1;
	if(idx >= n ) return AM_INVALID;
	int n_methods = buf[idx];
	idx++;
	while(idx < n && n_methods > 0) {
		if(buf[idx] == AM_NO_AUTH) {
			if(!auth_user) return AM_NO_AUTH;
			else if(use_auth_ips) {
				int authed = 0;
				if(pthread_rwlock_rdlock(&auth_ips_lock) == 0) {
					authed = is_in_authed_list(&client->addr);
					pthread_rwlock_unlock(&auth_ips_lock);
				}
				if(authed) return AM_NO_AUTH;
			}
		} else if(buf[idx] == AM_USERNAME) {
			if(auth_user) return AM_USERNAME;
		}
		idx++;
		n_methods--;
	}
	return AM_INVALID;
}

static int send_auth_response(int fd, int version, enum authmethod meth) {
	char buf[2];
	buf[0] = version;
	buf[1] = meth;
	ssize_t r = write(fd, buf, sizeof buf);
	return r == sizeof buf ? r : -1;
}

static int send_error(int fd, enum errorcode ec) {
	/* position 4 contains ATYP, the address type, which is the same as used in the connect
	   request. we're lazy and return always IPV4 address type in errors. */
	char buf[10] = { 5, ec, 0, 1 /*AT_IPV4*/, 0,0,0,0, 0,0 };
	ssize_t r = write(fd, buf, sizeof buf);
	return r == sizeof buf ? r : -1;
}

static void copyloop(int fd1, int fd2) {
	struct pollfd fds[2] = {
		[0] = {.fd = fd1, .events = POLLIN},
		[1] = {.fd = fd2, .events = POLLIN},
	};

	while(1) {
		/* inactive connections are reaped after 15 min to free resources.
		   usually programs send keep-alive packets so this should only happen
		   when a connection is really unused. */
		switch(poll(fds, 2, 60*15*1000)) {
			default: break;
			case 0:
				send_error(fd1, EC_TTL_EXPIRED);
				return;
			case -1:
				if(errno == EINTR || errno == EAGAIN) continue;
				else perror("poll");
				return;
		}
		int infd = (fds[0].revents & POLLIN) ? fd1 : fd2;
		int outfd = infd == fd2 ? fd1 : fd2;
		char buf[4096];
		ssize_t sent, n;
		int cycles = 32;
read_retry:
		sent = 0;
		if (--cycles <= 0) continue; // Don't let one channel monopolize.
		n = recv(infd, buf, sizeof buf, MSG_DONTWAIT);
		if (n == 0) return;
		if (n < 0) {
			switch (errno) {
			case EINTR:
				goto read_retry;
			case EAGAIN:
				continue;
			default: return;
			}
		}
		while(sent < n) {
			ssize_t m = write(outfd, buf+sent, n-sent);
			if(m < 0) {
				if (errno == EINTR) continue;
				return;
			}
			sent += m;
		}
		goto read_retry;
	}
}

static enum errorcode check_credentials(unsigned char* buf, size_t n) {
	if(n < 5) return EC_GENERAL_FAILURE;
	if(buf[0] != 1) return EC_GENERAL_FAILURE;
	unsigned ulen, plen;
	ulen=buf[1];
	if(n < 2 + ulen + 2) return EC_GENERAL_FAILURE;
	plen=buf[2+ulen];
	if(n < 2 + ulen + 1 + plen) return EC_GENERAL_FAILURE;
	char user[256], pass[256];
	memcpy(user, buf+2, ulen);
	memcpy(pass, buf+2+ulen+1, plen);
	user[ulen] = 0;
	pass[plen] = 0;
	if(!strcmp(user, auth_user) && !strcmp(pass, auth_pass)) return EC_SUCCESS;
	return EC_NOT_ALLOWED;
}

static void* clientthread(void *data) {
	auto t = static_cast<thread *>(data);
	t->state = SS_1_CONNECTED;
	unsigned char buf[1024];
	ssize_t n;
	int remotefd = -1;
	enum authmethod am;
	while((n = recv(t->client.fd, buf, sizeof buf, 0)) > 0) {
		switch(t->state) {
			case SS_1_CONNECTED:
				am = check_auth_method(buf, n, &t->client);
				if(am == AM_NO_AUTH) t->state = SS_3_AUTHED;
				else if (am == AM_USERNAME) t->state = SS_2_NEED_AUTH;
				if (send_auth_response(t->client.fd, 5, am) < 0) goto breakloop;
				if(am == AM_INVALID) goto breakloop;
				break;
			case SS_2_NEED_AUTH: {
				auto ret = check_credentials(buf, n);
				if (send_auth_response(t->client.fd, 1, am) < 0) goto breakloop;
				if(ret != EC_SUCCESS)
					goto breakloop;
				t->state = SS_3_AUTHED;
				if(use_auth_ips && !pthread_rwlock_wrlock(&auth_ips_lock)) {
					if(!is_in_authed_list(&t->client.addr))
						add_auth_ip(&t->client.addr);
					pthread_rwlock_unlock(&auth_ips_lock);
				}
				break;
			}
			case SS_3_AUTHED: {
				auto ret = connect_socks_target(buf, n, &t->client);
				if(ret < 0) {
					send_error(t->client.fd, static_cast<enum errorcode>(ret * -1));
					goto breakloop;
				}
				remotefd = ret;
				if (send_error(t->client.fd, EC_SUCCESS) < 0) goto breakloop;
				copyloop(t->client.fd, remotefd);
				goto breakloop;
			}
		}
	}
breakloop:

	if(remotefd != -1)
		close(remotefd);

	close(t->client.fd);
	t->done = 1;

	return 0;
}

static void collect(std::vector<thread *> &threads) {
	threads.erase(std::remove_if(threads.begin(), threads.end(),
                                     [&](thread *t) -> bool {
                                        if (t->done) {
                                            pthread_join(t->pt, 0);
                                            free(t);
                                            return true;
                                        }
                                        return false;
                                     }), threads.end());
}

static int usage(void) {
	dprintf(2,
		"MicroSocks SOCKS5 Server\n"
		"------------------------\n"
		"usage: microsocks -1 -i listenip -p port -u user -P password -b bindaddr\n"
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
	size_t i, l = strlen(s);
	for(i=0;i<l;i++) s[i] = 0;
}

int main(int argc, char** argv) {
	bind_addr.v4.sin_family = AF_UNSPEC;
	int ch;
	const char *listenip = "0.0.0.0";
	unsigned port = 1080;
	while((ch = getopt(argc, argv, ":146b:u:C:U:P:i:p:")) != -1) {
		switch(ch) {
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
				listenip = optarg;
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
	if((auth_user && !auth_pass) || (!auth_user && auth_pass)) {
		dprintf(2, "error: user and pass must be used together\n");
		return 1;
	}
	if(use_auth_ips && !auth_pass) {
		dprintf(2, "error: auth-once option must be used together with user/pass\n");
		return 1;
	}
	if(!allow_ipv6 && !allow_ipv4) {
		dprintf(2, "error: -4 and -6 options cannot be used together\n");
		return 1;
	}
	signal(SIGPIPE, SIG_IGN);
	struct server s;
	std::vector<thread *> threads;
	if(server_setup(&s, listenip, port)) {
		perror("server_setup");
		return 1;
	}
	server = &s;

	// XXX: Modified
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

	while(1) {
		collect(threads);
		struct client c;
		auto curr = static_cast<thread *>(malloc(sizeof (struct thread)));
		if(!curr) {
			usleep(16);
			continue;
		}
		curr->done = 0;
		if(server_waitclient(&s, &c)) {
			free(curr);
			continue;
		}
		curr->client = c;
		threads.push_back(curr);
		pthread_attr_t *a = 0, attr;
		if(pthread_attr_init(&attr) == 0) {
			a = &attr;
			pthread_attr_setstacksize(a, THREAD_STACK_SIZE);
		}
		if(pthread_create(&curr->pt, a, clientthread, curr) != 0)
			dolog("pthread_create failed. OOM?\n");
		if(a) pthread_attr_destroy(&attr);
	}
}
