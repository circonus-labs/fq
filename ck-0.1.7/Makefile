.PHONY: all clean distribution regressions install install-headers uninstall

CFLAGS=-D_XOPEN_SOURCE=600 -D_BSD_SOURCE -std=gnu99 -pedantic -Wall -W -Wundef -Wendif-labels -Wshadow -Wpointer-arith -Wbad-function-cast -Wcast-align -Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes -Wnested-externs -Winline -Wdisabled-optimization -fstrict-aliasing -O2 -pipe -Wno-parentheses 
VERSION=0.1.7
VERSION_MAJOR=0
PREFIX=/usr/local
LIBRARY=/usr/local/lib
HEADERS=/usr/local/include
PKGCONFIG_DATA=/usr/local/lib/pkgconfig

all:
	$(MAKE) -C src all || exit
	@echo
	@echo
	@echo ---[ Concurrency Kit has built successfully. You may now \"make install\".

regressions:
	$(MAKE) -C regressions all || exit
	@echo ---[ Regressions have built successfully.

install-headers:
	mkdir -p $(DESTDIR)/$(HEADERS) || exit
	cp include/*.h $(DESTDIR)/$(HEADERS) || exit
	chmod 644 $(DESTDIR)/$(HEADERS)/ck_*.h || exit
	mkdir -p $(DESTDIR)$(HEADERS)/gcc || exit
	cp -r include/gcc/* $(DESTDIR)/$(HEADERS)/gcc || exit
	chmod 755 $(DESTDIR)/$(HEADERS)/gcc
	chmod 644 $(DESTDIR)/$(HEADERS)/gcc/ck_*.h $(DESTDIR)/$(HEADERS)/gcc/*/ck_*.h || exit

install: all install-headers
	mkdir -p $(DESTDIR)/$(LIBRARY) || exit
	cp src/libck.so $(DESTDIR)/$(LIBRARY)/libck.so.$(VERSION) || exit
	ln -s $(LIBRARY)/libck.so.$(VERSION) $(DESTDIR)/$(LIBRARY)/libck.so
	ln -s $(LIBRARY)/libck.so.$(VERSION) $(DESTDIR)/$(LIBRARY)/libck.so.$(VERSION_MAJOR)
	chmod 744 $(DESTDIR)/$(LIBRARY)/libck.so* || exit
	mkdir -p $(DESTDIR)/$(PKGCONFIG_DATA) || exit
	chmod 755 $(DESTDIR)/$(PKGCONFIG_DATA)
	cp build/ck.pc $(DESTDIR)/$(PKGCONFIG_DATA)/ck.pc || exit
	cp src/libck.a $(DESTDIR)/$(LIBRARY)/libck.a || exit
	chmod 644 $(DESTDIR)/$(LIBRARY)/libck.a || exit

uninstall: 
	rm -f $(DESTDIR)/$(LIBRARY)/libck.so*
	rm -f $(DESTDIR)/$(LIBRARY)/libck.a
	rm -f $(DESTDIR)/$(HEADERS)/ck_*.h
	rm -f $(DESTDIR)/$(HEADERS)/gcc/ck_*.h
	rm -f $(DESTDIR)/$(HEADERS)/gcc/*/ck_*.h
	rm -f $(DESTDIR)/$(PKGCONFIG_DATA)/ck.pc

clean:
	$(MAKE) -C src clean
	$(MAKE) -C regressions clean
	rm -f *~ *.o

distribution: clean
	rm -f build/regressions.build
	rm -f build/ck.build
	rm -f build/ck.spec
	rm -f build/ck.pc
	rm -f Makefile
