.PHONY: all clean install

DUMP_SRC = pcr-dump.c
DUMP_BIN = pcr-dump
EXTEND_SRC = pcr-extend.c
EXTEND_BIN = pcr-extend
BINS = $(DUMP_BIN) $(EXTEND_BIN)

INSTALL ?= $(shell which install)
INSTALL_PROGRAM ?= $(INSTALL)
INSTALL_DATA ?= $(INSTALL) -m 0644

prefix ?= /usr/local
bindir ?= $(prefix)/bin

all : $(BINS)

clean :
	rm $(BINS)

install : $(BINS)
	$(INSTALL_PROGRAM) $^ $(DESTDIR)$(bindir)

uninstall :
	rm $(DESTDIR)$(bindir)/$(BINS)

$(DUMP_BIN) : LDLIBS=-ltspi
$(DUMP_BIN) : $(DUMP_SRC)

$(EXTEND_BIN) : LDLIBS=-ltspi -lcrypto
$(EXTEND_BIN) : $(EXTEND_SRC)
