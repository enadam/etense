#!/usr/bin/make

# Variables
CONFIG	:= -DCONFIG_MULTITHREAD=1
CFLAGS	:= -O0 -ggdb
#CFLAGS	:= -O2 -s
DESTDIR	:= /usr/local

HAVE_CMPXCHG += $(shell ./testif \
	-ok  -DHAVE_CMPXCHG=1 \
	-nok -DHAVE_CMPXCHG=0 \
	"static int foo(int a, int b)" \
	"{ return __sync_bool_compare_and_swap(&a, 0, b); }")
CONFIG += $(HAVE_CMPXCHG)

ifneq ($(filter -DCONFIG_MULTITHREAD=1,$(CONFIG)),)
ifeq  ($(filter -DHAVE_CMPXCHG=1,$(CONFIG)),)
HAVE_SPINLOCK += $(shell ./testif \
	-ok  -DHAVE_PTHREAD_SPINLOCK=1 \
	-nok -DHAVE_PTHREAD_SPINLOCK=0 \
	-flags -pthread \
	"\#include <pthread.h>" \
	"static pthread_spinlock_t lock;")
ifeq ($(HAVE_SPINLOCK),-DHAVE_PTHREAD_SPINLOCK=1)
CFLAGS += -pthread
endif
CONFIG += $(HAVE_SPINLOCK)
endif
endif

# How to determine the system's page size?
SYS_USER_H := $(shell ./testif \
	-ok  -DHAVE_SYS_USER_H=1 \
	-nok -DHAVE_SYS_USER_H=0 \
	"\#include <sys/user.h>" \
	"static unsigned long foo(void)" \
	"{ return PAGE_SIZE; }")
ifeq ($(SYS_USER_H),-DHAVE_SYS_USER_H=0)
CONFIG += $(shell ./testif -ok -DHAVE_GETPAGESIZE=1 \
	"\#include <unistd.h>" \
	"static unsigned long foo(void)" \
	"{ return getpagesize(); }")
else
CONFIG += $(SYS_USER_H)
endif

# Rules
all: libetense.so

libetense.so: etense.c etense.h
	cc -Wall -fPIC -shared $(CFLAGS) $(CONFIG) $< -o $@;
	chmod -x $@;
testeld: test.c libetense.so
	cc -Wall $(CFLAGS) -lm -ldl -L. -letense $(CONFIG) $< -o $@;
pretest: test.c
	cc -Wall $(CFLAGS) -lm -ldl -DCONFIG_ETENSE_PRELOAD $(CONFIG) \
		$< -o $@;

# Commands
.PHONY: all runtest install uninstall clean xclean

runtest: testeld pretest
	./test.pl testeld;
	./test.pl testeld -1;
	./test.pl pretest;
	./test.pl pretest -1;
install: libetense.so etense.h
	cp -f libetense.so $(DESTDIR)/lib;
	cp -f etense.h $(DESTDIR)/include;
uninstall:
	rm -f $(DESTDIR)/lib/libetense.so $(DESTDIR)/include/etense.h;
clean:
	rm -f testeld pretest;
xclean: clean
	rm -f libetense.so;

# End of Makefile
