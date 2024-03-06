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
* Use lock-free list rather than dynamic array for threads
* Minimal memory allocations after init, and low heap fragmentation
* Enhanced error handling

muonsocks fully supports SOCKS5 and SOCKS4a TCP proxying as a server.

It inherits the good design from microsocks, so the only real limits
are set by the available RAM and file descriptor limits.  OOM does not
cause termination, and explicit memory allocation and heap
fragmentation are minimized.

It is ~1000 LoC compared to microsocks's ~600 LoC, so it is not
as minimal, but it is still a very small program (~27KiB dynamically
linked to glibc on amd64).

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

`# muonsocks -u muonsocks -C /var/empty -4 -i 192.168.0.1 -i 10.0.0.1 -p 1080`

Which would run a SOCKS5 server listening for requests on 192.168.0.1:1080 and
10.0.0.1:1080 that would only send outgoing IPv4 requests.

I suggest running muonsocks from a process supervisor such as
[s6](http://www.skarnet.org/software/s6).  This will allow for reliable
functioning in the case of unforseen or unrecoverable errors.

For full information on command line options, run:

`$ muonsocks -?`

## History / Rationale

I previously used a SOCKS server that I wrote called nsocks.  It used an
event-driven model that attempted to use Linux's splice() to reduce
kernel->userspace->kernel copies.  However, the event-driven model
works better for pure servers such as HTTP than for proxies; buffering
is challenging to properly control in all cases for an event-driven
proxy, but is natural with threads and careful use of blocking writes.
splice() also gave marginal performance gains but made the program
significantly more complex.

I ended up using the original microsocks when I became tired of trying
to fix the many corner-cases in nsocks, and I expected to only use
it temporarily; there were some features I needed, which I added,
and I ported over some parts of nsocks that were well-tested such
as the SOCKS4 support.  Since nsocks was written in C++, I simply
used C++ rather than porting my own code to C.

After relatively little work, my local version of microsocks (which I
ended up calling muonsocks) worked trouble-free, and I ended up with
no motivation to write another server.  A few years later, I ended up
porting back to C and making further improvements.

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

    muonsocks -1 -i listenip -p port -U user -P password -b bindaddr

all arguments are optional.
by default listenip is 0.0.0.0 and port 1080.

option -1 activates auth_once mode: once a specific ip address
authed successfully with user/pass, it is added to a whitelist
and may use the proxy without auth.
this is handy for programs like firefox that don't support
user/pass auth. for it to work you'd basically make one connection
with another program that supports it, and then you can use firefox too.

