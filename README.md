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
* More robust and faster handling of DNS resolution and outgoing connections
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

It is ~1150 LoC compared to microsocks's ~600 LoC, so it is not
as minimal, but it is still a very small program (~35KiB dynamically
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
