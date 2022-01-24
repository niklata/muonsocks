# if you want to change/override some variables, do so in a file called
# config.mak, which is gets included automatically if it exists.

prefix = /usr/local
bindir = $(prefix)/bin

PROG = microsocks
SRCS =  main.cc privs.c
OBJS = main.o privs.o
DEPS = main.d privs.d

LIBS = -lpthread

CFLAGS = -MMD -O2 -s -std=c99 -Wall -pedantic -Wextra -Wformat=2 -Wformat-nonliteral -Wformat-security -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_GNU_SOURCE
CXXFLAGS = -MMD -O2 -s -std=gnu++17 -fno-rtti -fno-exceptions -Wall -pedantic -Wextra -Wformat=2 -Wformat-nonliteral -Wformat-security -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_GNU_SOURCE
CPPFLAGS += $(INC)

#CFLAGS += -fsanitize=undefined
#CXXFLAGS += -fsanitize=undefined
#LDFLAGS += -fsanitize=undefined

-include config.mak

all: $(PROG)

$(PROG): $(OBJS)
	$(CXX) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

-include $(DEPS)

install: $(PROG)
	install -d $(DESTDIR)/$(bindir)
	install -D -m 755 $(PROG) $(DESTDIR)/$(bindir)/$(PROG)

clean:
	rm -f $(PROG) $(OBJS) $(DEPS)

.PHONY: all clean install

