all: pcapsipdump

pcapsipdump: pcapsipdump.cpp calltable.cpp calltable.h
	$(CC) $(CPPFLAGS) $(LDFLAGS) pcapsipdump.cpp calltable.cpp -o pcapsipdump -lpcap -lstdc++

pcapsipdump-debug: pcapsipdump.cpp calltable.cpp calltable.h
	$(CC) $(CPPFLAGS) $(LDFLAGS) -ggdb pcapsipdump.cpp calltable.cpp -o pcapsipdump-debug -lpcap -lstdc++

clean:
	rm -f pcapsipdump

install:
	install pcapsipdump ${DESTDIR}/usr/sbin/pcapsipdump
	install redhat/pcapsipdump.init ${DESTDIR}/etc/rc.d/init.d/pcapsipdump
	install redhat/pcapsipdump.sysconfig ${DESTDIR}/etc/sysconfig/pcapsipdump
	mkdir -p ${DESTDIR}/var/spool/pcapsipdump
	chmod 0700 ${DESTDIR}/var/spool/pcapsipdump
