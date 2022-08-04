# muonsocks

## Introduction

This is an enhancement of rofl0r's excellent
[microsocks](https://github.com/rofl0r/microsocks) program with the following
changes:

* Support SOCKS4a clients
* Support disabling outgoing ipv4 or ipv6
* Support changing uid and chroot
* Support binding to multiple ip/port tuples
* Rewritten SOCKS5 parser that tolerates inputs split across multiple recv()
* More performance from larger buffers and fewer poll invocations
* Use TCP_NODELAY to lower latency impact
* Enhanced error handling
* Correct some minor bugs (signal handling and memory leaks)

It is compiled as C++ rather than C essentially for destructors and the RAII
idiom.  Exceptions or RTTI are not used, so bloat is minimal.

muonsocks obsoletes nsocks; it is strictly superior aside from having no
support for UDP over SOCKS which is virtually never used in practice.

## Requirements

* Linux or BSD system
* GCC or Clang
* GNU Make

## Standard Usage

Compile and install muonsocks.
* Build muonsocks: `make`
* Install the `muonsocks` executable in a normal place.  I suggest
  `/usr/local/bin`.

Set up the user account and chroot directory for muonsocks.  Example:
```
$ su -
# umask 077
# groupadd muonsocks
# useradd -d /var/empty -s /sbin/nologin -g muonsocks muonsocks
```

Then the program can be run similarly to:

`# muonsocks -u muonsocks -C /var/empty -4 -b 192.168.0.1 -b 10.0.0.1 -p 1080`

Which would run a SOCKS5 server bound to 192.168.0.1:1080 and 10.0.0.1:1080
that would only send outgoing IPv4 requests.

I suggest running muonsocks from a process supervisor such as
[s6](http://www.skarnet.org/software/s6).  This will allow for reliable
functioning in the case of unforseen or unrecoverable errors.

## Downloads

* [GitLab](https://gitlab.com/niklata/muonsocks)
* [Codeberg](https://codeberg.org/niklata/muonsocks)
* [BitBucket](https://bitbucket.com/niklata/muonsocks)
* [GitHub](https://github.com/niklata/muonsocks)

## Original microsocks README below

MicroSocks - multithreaded, small, efficient SOCKS5 server.
===========================================================

a SOCKS5 service that you can run on your remote boxes to tunnel connections
through them, if for some reason SSH doesn't cut it for you.

It's very lightweight, and very light on resources too:

for every client, a thread with a stack size of 8KB is spawned.
the main process basically doesn't consume any resources at all.

the only limits are the amount of file descriptors and the RAM.

It's also designed to be robust: it handles resource exhaustion
gracefully by simply denying new connections, instead of calling abort()
as most other programs do these days.

another plus is ease-of-use: no config file necessary, everything can be
done from the command line and doesn't even need any parameters for quick
setup.

History
-------

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

command line options
------------------------

    muonsocks -1 -i listenip -p port -u user -P password -b bindaddr

all arguments are optional.
by default listenip is 0.0.0.0 and port 1080.

option -1 activates auth_once mode: once a specific ip address
authed successfully with user/pass, it is added to a whitelist
and may use the proxy without auth.
this is handy for programs like firefox that don't support
user/pass auth. for it to work you'd basically make one connection
with another program that supports it, and then you can use firefox too.

