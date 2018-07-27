# If you want a verbose make (visible commands) add V=1 to you invocation

.SUFFIXES: .lo

CC=gcc
LD=gcc
LN_S=ln -s
COPT=-O5
TAR=tar
SED=sed
PREFIX=/usr/local
INCLUDEDIR=$(PREFIX)/include
LIBDIR=$(PREFIX)/lib
LIBEXECDIR=$(PREFIX)/libexec
BINDIR=$(PREFIX)/bin
SBINDIR=$(PREFIX)/sbin
VARLIBFQ=$(PREFIX)/var/lib/fq
INSTALL=install
SHLD=$(LD) -shared
MODULELD=$(LD) -shared
LIBEXT=so
SHCFLAGS=-fPIC
DTRACE=/usr/sbin/dtrace
OS=$(shell uname)

FQ_MAJOR=0
FQ_MINOR=10
FQ_MICRO=12

Q=
ifeq ($(V),)
	Q=@
endif

VENDOR_CFLAGS=
VENDOR_LDFLAGS=
DTRACEFLAGS=
EXTRA_CFLAGS=$(VENDOR_CFLAGS) -g -D_REENTRANT -m64 -D_BSD_SOURCE -std=gnu99 -pedantic -Wall
EXTRA_CFLAGS+=-DVARLIBFQDIR=\"$(VARLIBFQ)\"
EXTRA_CFLAGS+=-DLIBEXECDIR=\"$(LIBEXECDIR)\"
#EXTRA_CFLAGS+=-DDEBUG

CLIENT_OBJ=fq_client.o fq_msg.o fq_utils.o
CLIENT_OBJ_LO=$(CLIENT_OBJ:%.o=%.lo)
FQD_OBJ=fqd.o fqd_listener.o fqd_ccs.o fqd_dss.o fqd_config.o \
	fqd_queue.o fqd_routemgr.o fqd_queue_mem.o fqd_queue_jlog.o \
	fqd_http.o fqd_prog.o fqd_peer.o http_parser.o \
	$(CLIENT_OBJ)
FQC_OBJ=fqc.o $(CLIENT_OBJ)
FQD_SAMPLE_OBJ=fqd_dyn_sample.lo
FQD_DTRACE_OBJ=

FQDLIBS=-ljlog -lsqlite3
LIBS+=-lck

SHLDFLAGS=
ifeq ($(OS),SunOS)
SHLDFLAGS+=-R$(LIBDIR)
LIBS+=-lcrypto -lsocket -lnsl -lumem -luuid
LIBLIBS+=-luuid -lsocket -lnsl
EXTRA_CFLAGS+=-D_XOPEN_SOURCE=600 
EXTRA_CFLAGS+=-D__EXTENSIONS__ -DHAVE_UINTXX_T -DSIZEOF_LONG_LONG_INT=8 -m64 -D_REENTRANT -DHAVE_GETHOSTBYNAME_R
EXTRA_SHLDFLAGS=-m64
FQD_DTRACE_OBJ=fq_dtrace.o
DTRACEFLAGS=-xnolibs
else
ifeq ($(OS),Darwin)
MODULELD=ld -bundle
LOADER=-bundle_loader fqd -lc
COPT=-O3
EXTRA_CFLAGS+=-D_DARWIN_C_SOURCE -DHAVE_U_INTXX_T -DHAVE_INTXX_T -DHAVE_U_INT64_T -DHAVE_INT64_T \
	-Wno-dollar-in-identifier-extension -Wno-gnu-statement-expression -Wno-deprecated-declarations
#EXTRA_CFLAGS+=-Weverything
LIBEXT=dylib
else
ifeq ($(OS),Linux)
EXTRA_CFLAGS+=-D_XOPEN_SOURCE=600 
SHLDFLAGS+=-Wl,-rpath=$(LIBDIR)
LDFLAGS+=-rdynamic -export-dynamic
LIBS+=-lcrypto -lpthread -ldl -luuid -lrt 
LIBLIBS+=-lpthread -luuid -lrt
else
ifeq ($(OS),FreeBSD)
SHLDFLAGS+=-Wl,-rpath=$(LIBDIR)
LDFLAGS+=-rdynamic
LIBS+=-lcrypto -lpthread -luuid -lexecinfo
LIBLIBS+=-lpthread -luuid -lexecinfo
FQD_DTRACE_OBJ=fq_dtrace.o
endif
endif
endif
endif

all:	libfq.$(LIBEXT) libfq.a fqd fqc fqtool fq_sndr fq_rcvr fq_bench java/fqclient.jar fq-sample.so

include Makefile.depend

SHLDFLAGS+=$(VENDOR_LDFLAGS) -m64 -L$(LIBDIR)
ifeq ($(OS),Darwin)
SHLDFLAGS+=-current_version $(FQ_MAJOR).$(FQ_MINOR).$(FQ_MICRO) -install_name $(LIBDIR)/libfq.$(FQ_MAJOR).dylib
SOLONG=libfq.$(FQ_MAJOR).$(FQ_MINOR).$(FQ_MICRO).dylib
SOSHORT=libfq.$(FQ_MAJOR).dylib
LIBNAME=libfq.dylib
else
SHLDFLAGS+=-Wl,-soname,libfq.so.$(FQ_MAJOR)
SOLONG=libfq.so.$(FQ_MAJOR).$(FQ_MINOR).$(FQ_MICRO)
SOSHORT=libfq.so.$(FQ_MAJOR)
LIBNAME=libfq.so
endif

CFLAGS+=$(EXTRA_CFLAGS)
SHCFLAGS+=$(EXTRA_CFLAGS)
LDFLAGS+=$(VENDOR_LDFLAGS)

fqd.h:	fqd.h.in
	sed -e 's/@@FQ_MAJOR@@/'$(FQ_MAJOR)'/g;' \
		-e 's/@@FQ_MINOR@@/'$(FQ_MINOR)'/g;' \
		-e 's/@@FQ_MICRO@@/'$(FQ_MICRO)'/g;' < fqd.h.in > fqd.h

fq_dtrace.h:	fq_dtrace.d
	-$(DTRACE) $(DTRACEFLAGS) -h -o $@ -s $<
	if [ ! -f $@ ]; then cp fq_dtrace.blank.h $@; fi

fq_dtrace.o: $(FQD_OBJ)
	$(DTRACE) $(DTRACEFLAGS) -64 -G -s fq_dtrace.d -o $@ $(FQD_OBJ)

fq_dtrace.blank.h:	fq_dtrace.h
	awk 'BEGIN{print "#if 0"} /#else/,/#endif/{print}' $< > $@

fqd:	$(FQD_OBJ) $(FQD_DTRACE_OBJ)
	@echo " - linking $@"
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(FQD_OBJ) $(FQD_DTRACE_OBJ) $(LIBS) $(FQDLIBS)

fqc:	$(FQC_OBJ)
	@echo " - linking $@"
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(FQC_OBJ) $(LIBS)

fq-sample.so:	fqd $(FQD_SAMPLE_OBJ)
	$(Q)$(MODULELD) $(LOADER) $(EXTRA_SHLDFLAGS) -o $@ $(FQD_SAMPLE_OBJ)

fq_sndr:	fq_sndr.o libfq.a
	@echo " - linking $@"
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -L. -lfq -o $@ $^ $(LIBS)

fqs:	fqs.o libfq.a
	@echo " - linking $@"
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -L. -lfq -o $@ $^ $(LIBS)

fq_rcvr:	fq_rcvr.o libfq.a
	@echo " - linking $@"
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -L. -lfq -o $@ $^ $(LIBS)

fqtool:	fqtool.o libfq.a
	@echo " - linking $@"
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -L. -lfq -o $@ $^ $(LIBS)

fq_bench:	fq_bench.o libfq.a
	@echo " - linking $@"
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -L. -lfq -o $@ $^ $(LIBS)

libfq.$(LIBEXT):	$(CLIENT_OBJ_LO)
	@echo " - creating $@"
	$(Q)$(SHLD) $(EXTRA_SHLDFLAGS) $(SHLDFLAGS) -o $@ $(CLIENT_OBJ_LO) $(LIBLIBS)

libfq.a:	$(CLIENT_OBJ)
	@echo " - creating $@"
	$(Q)ar cr $@ $(CLIENT_OBJ)

.c.o:	$<
	@echo " - compiling $<"
	$(Q)$(CC) $(CPPFLAGS) $(CFLAGS) $(COPT) -o $@ -c $<

.c.lo:	$<
	@echo " - compiling $<"
	$(Q)$(CC) $(CPPFLAGS) $(SHCFLAGS) -o $@ -c $<

Makefile.depend:	fq_dtrace.h fqd.h
	@echo " - make depend"
	$(Q)$(CC) $(CPPFLAGS) $(CFLAGS) -MM *.c > Makefile.depend

java/fqclient.jar:
	(cd java && $(MAKE) fqclient.jar)

install:	all
	$(INSTALL) -d $(DESTDIR)/$(INCLUDEDIR)
	$(INSTALL) -m 0444 fq.h $(DESTDIR)/$(INCLUDEDIR)/fq.h
	$(INSTALL) -d $(DESTDIR)/$(LIBDIR)
	$(INSTALL) -m 0444 libfq.a $(DESTDIR)/$(LIBDIR)/libfq.a
	$(INSTALL) -m 0555 libfq.$(LIBEXT) $(DESTDIR)/$(LIBDIR)/$(SOLONG)
	$(LN_S) -f $(SOLONG) $(DESTDIR)/$(LIBDIR)/$(SOSHORT)
	$(LN_S) -f $(SOLONG) $(DESTDIR)/$(LIBDIR)/$(LIBNAME)
	$(INSTALL) -d $(DESTDIR)/$(LIBEXECDIR)
	$(INSTALL) -m 0555 fq-sample.so $(DESTDIR)/$(LIBEXECDIR)/fq-sample.so
	$(INSTALL) -d $(DESTDIR)/$(BINDIR)
	$(INSTALL) -m 0555 fqtool $(DESTDIR)/$(BINDIR)/fqtool
	$(INSTALL) -m 0555 fqs $(DESTDIR)/$(BINDIR)/fqs
	$(INSTALL) -d $(DESTDIR)/$(SBINDIR)
	$(INSTALL) -m 0555 fqd $(DESTDIR)/$(SBINDIR)/fqd
	$(INSTALL) -d $(DESTDIR)$(VARLIBFQ)
	$(TAR) cf - web | (cd $(DESTDIR)$(VARLIBFQ) && $(TAR) xf -)
	$(INSTALL) -d $(DESTDIR)/usr/lib/dtrace
	$(INSTALL) -m 0444 fq.d $(DESTDIR)/usr/lib/dtrace/fq.d

clean:
	rm -f *.o *.a fqc fqd *.$(LIBEXT) fq_dtrace.h
