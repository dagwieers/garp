DEBUG=-g
CFLAGS=-O2 -Wall $(DEBUG)
LDFLAGS=-O2 $(DEBUG)
prefix=/
MANDIR=/usr/man/man8/
INSTALL=install

all: garp
garp: garp.o

garp.o: garp.c

install: all install-code install-data

install-code:
	$(INSTALL) -d -m 755 $(prefix)/sbin
	$(INSTALL) -o root -g root -m 755 garp $(prefix)sbin
install-data:
	$(INSTALL) -d -m 755 $(MANDIR)
	$(INSTALL) -m 644 garp.8 $(MANDIR)garp.8

.PHONY: clean
clean:
	-rm garp garp.o
