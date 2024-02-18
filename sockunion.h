#ifndef SOCKUNION_H
#define SOCKUNION_H

#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

union sockaddr_union {
    struct sockaddr_in  v4;
    struct sockaddr_in6 v6;
};

#define SOCKADDR_UNION_AF(PTR) (PTR)->v4.sin_family

#define SOCKADDR_UNION_LENGTH(PTR) ( \
    ( SOCKADDR_UNION_AF(PTR) == AF_INET  ) ? sizeof((PTR)->v4) : ( \
    ( SOCKADDR_UNION_AF(PTR) == AF_INET6 ) ? sizeof((PTR)->v6) : 0 ) )

#define SOCKADDR_UNION_ADDRESS(PTR) ( \
    ( SOCKADDR_UNION_AF(PTR) == AF_INET  ) ? (void *)&(PTR)->v4.sin_addr  : ( \
    ( SOCKADDR_UNION_AF(PTR) == AF_INET6 ) ? (void *)&(PTR)->v6.sin6_addr : NULL ) )

#define SOCKADDR_UNION_PORT(PTR) ( \
    ( SOCKADDR_UNION_AF(PTR) == AF_INET  ) ? (PTR)->v4.sin_port  : ( \
    ( SOCKADDR_UNION_AF(PTR) == AF_INET6 ) ? (PTR)->v6.sin6_port : 0 ) )

#endif

