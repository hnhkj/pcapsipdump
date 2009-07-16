LIBS ?= -lpcap -lstdc++

all: pcapsipdump

pcapsipdump: pcapsipdump.cpp calltable.cpp calltable.h
	$(CC) $(CPPFLAGS) $(LDFLAGS) $(LIBS) pcapsipdump.cpp calltable.cpp -o pcapsipdump

pcapsipdump-debug: pcapsipdump.cpp calltable.cpp calltable.h
	$(CC) $(CPPFLAGS) $(LDFLAGS) $(LIBS) -ggdb pcapsipdump.cpp calltable.cpp -o pcapsipdump-debug

clean:
	rm -f pcapsipdump

install:
	install pcapsipdump ${DESTDIR}/usr/sbin/pcapsipdump
	install redhat/pcapsipdump.init ${DESTDIR}/etc/init.d/pcapsipdump
	install redhat/pcapsipdump.sysconfig ${DESTDIR}/etc/sysconfig/pcapsipdump
	mkdir -p ${DESTDIR}/var/spool/pcapsipdump
	chmod 0700 ${DESTDIR}/var/spool/pcapsipdump
