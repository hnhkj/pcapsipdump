include make-checks/*.mk

#uncommend next line for regex support
#DEFS ?= -DUSE_REGEXP
LIBS ?= -lpcap -lstdc++
RELEASEFLAGS ?= -O3

all: pcapsipdump

pcapsipdump: make-checks pcapsipdump.cpp calltable.cpp calltable.h
	$(CC) $(RELEASEFLAGS) $(CPPFLAGS) $(LDFLAGS) $(LIBS) $(DEFS) pcapsipdump.cpp calltable.cpp -o pcapsipdump

pcapsipdump-debug: make-checks pcapsipdump.cpp calltable.cpp calltable.h
	$(CC) $(CPPFLAGS) $(LDFLAGS) $(LIBS) $(DEFS) -ggdb pcapsipdump.cpp calltable.cpp -o pcapsipdump-debug

clean:
	rm -f pcapsipdump

install:
	install pcapsipdump ${DESTDIR}/usr/sbin/pcapsipdump
	install redhat/pcapsipdump.init ${DESTDIR}/etc/rc.d/init.d/pcapsipdump
	install redhat/pcapsipdump.sysconfig ${DESTDIR}/etc/sysconfig/pcapsipdump
	mkdir -p ${DESTDIR}/var/spool/pcapsipdump
	chmod 0700 ${DESTDIR}/var/spool/pcapsipdump

install-debian:
	install pcapsipdump ${DESTDIR}/usr/sbin/pcapsipdump
	install debian/pcapsipdump.init ${DESTDIR}/etc/init.d/pcapsipdump
	install debian/pcapsipdump.default ${DESTDIR}/etc/default/pcapsipdump
	mkdir -p ${DESTDIR}/var/spool/pcapsipdump
	chmod 0700 ${DESTDIR}/var/spool/pcapsipdump
