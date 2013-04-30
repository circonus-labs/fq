JAVAC=javac
JAR=jar

JAVAFILES=\
	com/omniti/labs/FqClient.java \
	com/omniti/labs/FqClientImplDebug.java \
	com/omniti/labs/FqClientImplInterface.java \
	com/omniti/labs/FqClientImplNoop.java \
	com/omniti/labs/FqCommand.java \
	com/omniti/labs/FqCommandProtocolError.java \
	com/omniti/labs/FqDataProtocolError.java \
	com/omniti/labs/FqHeartbeatException.java \
	com/omniti/labs/FqMessage.java

all:	fqclient.jar

fqclient.jar:	$(JAVAFILES:%=src/%)
	mkdir -p classes
	(cd src && $(JAVAC) -d ../classes $(JAVAFILES))
	$(JAR) cf $@ -C classes .

fq_rcvr.class:	fq_rcvr.java fqclient.jar
	$(JAVAC) -cp fqclient.jar fq_rcvr.java

clean:
	rm -f fqclient.jar
	rm -f *.class
	rm -rf classes
