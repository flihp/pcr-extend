.PHONY: all clean install

EXTEND_SRC = pcr-extend.c
EXTEND_BIN = pcr-extend

INSTALL ?= $(shell which install)
INSTALL_PROGRAM ?= $(INSTALL)
INSTALL_DATA ?= $(INSTALL) -m 0644

prefix ?= /usr/local
bindir ?= $(prefix)/bin

all : $(EXTEND_BIN)

clean :
	rm $(EXTEND_BIN)

install : $(EXTEND_BIN)
	$(INSTALL_PROGRAM) $^ $(DESTDIR)$(bindir)

uninstall :
	rm $(DESTDIR)$(bindir)/$(EXTEND_BIN)

$(EXTEND_BIN) : LDLIBS=-ltspi -lcrypto
$(EXTEND_BIN) : $(EXTEND_SRC)
