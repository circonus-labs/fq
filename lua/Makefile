fqclient.lua:
	./generatelua.sh

install: fqclient.lua
	install --mode=0644 fqclient.lua /usr/local/share/luajit-2.1.0-alpha/
	install --mode=0755 fq-sender fq-receiver fq-proxy /usr/local/bin/
