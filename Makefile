#uncommend next line for regex support
#DEFS ?= -DUSE_REGEXP
LIBS ?= -lpcap -lstdc++
RELEASEFLAGS ?= -O3 -Wall

# auto-detect if bsd/strings.h is available
ifneq ($(shell ldconfig -p |grep libbsd.so),)
	BSDSTR_DEFS := -DUSE_BSD_STRING_H
	BSDSTR_LIBS := -lbsd
endif

# auto-detect rhel/fedora and debian/ubuntu
ifneq ($(wildcard /etc/redhat-release),)
	EXTRA_INSTALL := install-redhat
endif
ifneq ($(wildcard /etc/debian_version),)
	EXTRA_INSTALL := install-debian
endif

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

install: $(EXTRA_INSTALL)
	install pcapsipdump ${DESTDIR}/usr/sbin/pcapsipdump
	mkdir -p ${DESTDIR}/var/spool/pcapsipdump
	chmod 0700 ${DESTDIR}/var/spool/pcapsipdump

install-redhat:
	install redhat/pcapsipdump.init ${DESTDIR}/etc/rc.d/init.d/pcapsipdump
	install redhat/pcapsipdump.sysconfig ${DESTDIR}/etc/sysconfig/pcapsipdump

install-debian:
	install debian/pcapsipdump.init ${DESTDIR}/etc/init.d/pcapsipdump
	install debian/pcapsipdump.default ${DESTDIR}/etc/default/pcapsipdump
