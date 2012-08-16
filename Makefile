CC=gcc
DTRACE=/usr/sbin/dtrace
CKDIR=ck-0.2
OS=$(shell uname)

EXTRA_CFLAGS=-g -D_REENTRANT
EXTRA_CFLAGS+=-DDEBUG

CLIENT_OBJ=fq_client.o fq_msg.o fq_utils.o
FQD_OBJ=fqd.o fqd_listener.o fqd_ccs.o fqd_dss.o fqd_config.o \
	fqd_queue.o fqd_routemgr.o fqd_queue_mem.o fqd_prog.o \
	$(CLIENT_OBJ)
FQC_OBJ=fqc.o $(CLIENT_OBJ)
JLOG_OBJ=jlog/jlog.o jlog/jlog_hash.o jlog/jlog_io.o
FQD_DTRACE_OBJ=
CPPFLAGS=-I./$(CKDIR)/include

ifeq ($(OS),SunOS)
LIBS=-lsocket -lnsl -lumem -luuid
EXTRA_CFLAGS+=-D__EXTENSIONS__
FQD_DTRACE_OBJ=fq_dtrace.o
else
ifeq ($(OS),Darwin)
EXTRA_CFLAGS+=-D_DARWIN_C_SOURCE
endif
endif

all:	libfq.a fqd fqc fq_sndr fq_rcvr

Makefile.build:
	(cd $(CKDIR) && ./configure)
	sed -e 's:\.\./build:'$(CKDIR)'/build:g' \
		-e 's/CFLAGS=/CPPFLAGS+=/g' \
		-e 's/LDFLAGS/SHLDFLAGS/g' \
		< $(CKDIR)/build/ck.build \
		> $@

include Makefile.build
include Makefile.depend

CFLAGS+=$(EXTRA_CFLAGS)

fq_dtrace.h:	fq_dtrace.d
	-$(DTRACE) -h -o $@ -s $<
	if [ ! -f $@ ]; then cp fq_dtrace.blank.h $@; fi

fq_dtrace.o: $(FQD_OBJ)
	$(DTRACE) -64 -G -s fq_dtrace.d -o $@ $(FQD_OBJ)

fq_dtrace.blank.h:	fq_dtrace.h
	awk 'BEGIN{print "#if 0"} /#else/,/#endif/{print}' $< > $@

jlog/libjlog.a:	$(JLOG_OBJ)
	@echo " - archiving $@"
	@ar cq $@ $(JLOG_OBJ)

fqd:	$(FQD_OBJ) $(FQD_DTRACE_OBJ) jlog/libjlog.a
	@echo " - linking $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(FQD_OBJ) $(FQD_DTRACE_OBJ) $(LIBS) -Ljlog -ljlog

fqc:	$(FQC_OBJ)
	@echo " - linking $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(FQC_OBJ) $(LIBS)

fq_sndr:	fq_sndr.o libfq.a
	@echo " - linking $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -L. -lfq -o $@ $^ $(LIBS)

fq_rcvr:	fq_rcvr.o libfq.a
	@echo " - linking $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -L. -lfq -o $@ $^ $(LIBS)

libfq.a:	$(CLIENT_OBJ)
	@echo " - creating $@"
	@ar cr $@ $(CLIENT_OBJ)

.c.o:	$<
	@echo " - compiling $<"
	@$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

Makefile.depend:	fq_dtrace.h
	@echo " - make depend"
	@$(CC) $(CPPFLAGS) $(CFLAGS) -MM *.c > Makefile.depend

clean:
	rm -f *.o *.a fqc fqd jlog/*.a jlog/*.o
