# if you want to change/override some variables, do so in a file called
# config.mak, which is gets included automatically if it exists.

prefix = /usr/local
bindir = $(prefix)/bin

PROG = microsocks
SRCS =  sockssrv.cc server.cc privs.c
OBJS = sockssrv.o server.o privs.o
#OBJS = $(SRCS:.c=.o)

LIBS = -lpthread

CFLAGS += -std=c99 -Wall -pedantic -Wextra -Wformat=2 -Wformat-nonliteral -Wformat-security -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_GNU_SOURCE
CPPFLAGS += -std=gnu++17 -fno-rtti -fno-exceptions -Wall -pedantic -Wextra -Wformat=2 -Wformat-nonliteral -Wformat-security -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_GNU_SOURCE

-include config.mak

all: $(PROG)

install: $(PROG)
	install -d $(DESTDIR)/$(bindir)
	install -D -m 755 $(PROG) $(DESTDIR)/$(bindir)/$(PROG)

clean:
	rm -f $(PROG)
	rm -f $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) $(INC) $(PIC) -c -o $@ $<

$(PROG): $(OBJS)
	$(CXX) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

.PHONY: all clean install

