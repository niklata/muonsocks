# if you want to change/override some variables, do so in a file called
# config.mak, which is gets included automatically if it exists.

prefix = /usr/local
bindir = $(prefix)/bin

PROG = muonsocks
C_SRCS =  $(sort nk/privs.c main.c)
OBJS = $(C_SRCS:.c=.o) $(CXX_SRCS:.cc=.o)
DEPS = $(C_SRCS:.c=.d) $(CXX_SRCS:.cc=.d)

CFLAGS = -MMD -O2 -flto -s -std=c17 -I. -Wall -pedantic -Wextra -Wformat=2 -Wformat-nonliteral -Wformat-security -Wshadow -Wpointer-arith -Wmissing-prototypes -Wcast-qual -Wsign-conversion -Wstrict-overflow=5 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_GNU_SOURCE
CPPFLAGS += $(INC)

#CFLAGS += -fsanitize=undefined
#LDFLAGS += -fsanitize=undefined

-include config.mak

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -nodefaultlibs -lgcc -lc -lpthread -o $@ $^

-include $(DEPS)

install: $(PROG)
	install -d $(DESTDIR)/$(bindir)
	install -D -m 755 $(PROG) $(DESTDIR)/$(bindir)/$(PROG)

clean:
	rm -f $(PROG) $(OBJS) $(DEPS)

.PHONY: all clean install

