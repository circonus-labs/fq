CC=gcc
CKDIR=ck-0.1.7

EXTRA_CFLAGS=-g -D_REENTRANT
#EXTRA_CFLAGS+=-DDEBUG

CLIENT_OBJ=fq_client.o fq_msg.o fq_utils.o
FQD_OBJ=fqd.o fqd_listener.o fqd_ccs.o fqd_dss.o fqd_config.o \
	fqd_queue.o fqd_routemgr.o fqd_queue_mem.o \
	$(CLIENT_OBJ)
FQC_OBJ=fqc.o $(CLIENT_OBJ)
CPPFLAGS=-I./$(CKDIR)/include

all:	libfq.a fqd fqc

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

fqd:	$(FQD_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(FQD_OBJ)

fqc:	$(FQC_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(FQC_OBJ)

libfq.a:	$(CLIENT_OBJ)
	ar cr $@ $(CLIENT_OBJ)

.c.o:	$<
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

Makefile.depend:
	$(CC) $(CPPFLAGS) $(CFLAGS) -MM *.c > Makefile.depend

clean:
	rm -f *.o *.a fqc fqd
