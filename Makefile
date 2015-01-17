#uncommend next line for regex support
#DEFS ?= -DUSE_REGEXP
LIBS ?= -lpcap -lstdc++
RELEASEFLAGS ?= -O3 -Wall

BSDSTR_DEFS := $(shell ldconfig -p |grep -q libbsd.so && \
    echo -DUSE_BSD_STRING_H)

BSDSTR_LIBS := $(shell ldconfig -p |grep -q libbsd.so && \
    echo -lbsd)

all: make-checks/all pcapsipdump

include make-checks/*.mk

pcapsipdump: pcapsipdump.cpp calltable.cpp calltable.h
	$(CXX) $(RELEASEFLAGS) $(CXXFLAGS) $(LDFLAGS) $(DEFS) $(BSDSTR_DEFS) \
	pcapsipdump.cpp calltable.cpp $(LIBS) $(BSDSTR_LIBS) \
       	-o pcapsipdump

pcapsipdump-debug: make-checks pcapsipdump.cpp calltable.cpp calltable.h
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(DEFS) $(BSDSTR_DEFS) -ggdb \
	pcapsipdump.cpp calltable.cpp $(LIBS) $(BSDSTR_LIBS) \
	-o pcapsipdump-debug

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
