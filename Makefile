# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2019 Brett Sheffield <brett@gladserv.com>

PREFIX = /usr/local
export PREFIX

CFLAGS += -O -Wall -Werror -g
export CFLAGS

BIN_PATH = $(PREFIX)/sbin
export BIN_PATH

.PHONY: all clean realclean src

all:
	@$(MAKE) -C src $@

clean:
	@$(MAKE) -C src $@

realclean:
	@$(MAKE) -C src $@

install:
	@$(MAKE) -C src $@
	@$(MAKE) -C doc $@

src:
	@$(MAKE) -C src all

