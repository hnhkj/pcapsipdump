all: pcapsipdump

pcapsipdump: pcapsipdump.cpp calltable.cpp calltable.h
	c++ -s -Wall -O2 -fomit-frame-pointer pcapsipdump.cpp calltable.cpp -o pcapsipdump -lpcap

pcapsipdump-debug: pcapsipdump.cpp calltable.cpp calltable.h
	c++ -ggdb -Wall pcapsipdump.cpp calltable.cpp -o pcapsipdump-debug -lpcap

clean:
	rm -f pcapsipdump

install:
	install pcapsipdump ${DESTDIR}/usr/sbin/pcapsipdump
	install redhat/pcapsipdump.init ${DESTDIR}/etc/rc.d/init.d/pcapsipdump
	install redhat/pcapsipdump.sysconfig ${DESTDIR}/etc/sysconfig/pcapsipdump
	mkdir -p ${DESTDIR}/var/spool/pcapsipdump
	chmod 0700 ${DESTDIR}/var/spool/pcapsipdump
