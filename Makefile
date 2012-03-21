CC=gcc
CKDIR=ck-0.1.7

CLIENT_OBJ=fq_client.o
FQD_OBJ=fqd.o $(CLIENT_OBJ)
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

CFLAGS+=$(EXTRA_CFLAGS)

fqd:	$(FQD_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(FQD_OBJ)

fqc:	$(FQC_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(FQC_OBJ)

libfq.a:	$(CLIENT_OBJ)
	ar cr $@ $(CLIENT_OBJ)

.c.o:	$<
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

clean:
	rm -f *.o *.a fqc fqd
