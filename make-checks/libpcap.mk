CHECK_LIBPCAP = $(CXX) $(CXXFLAGS) $(LDFLAGS) -lpcap make-checks/libpcap.cpp -o make-checks/libpcap

make-checks/libpcap:
	@$(CHECK_LIBPCAP) || (\
	  echo; \
	  echo $(CHECK_LIBPCAP); \
	  echo; \
	  echo "Required library not found: pcap "; \
	  echo "Please install it in your distribution-specific manner, e.g.:"; \
	  echo " yum install libpcap libpcap-devel"; \
	  echo " apt-get install libpcap libpcap-dev"; \
	  echo " cd ~ports/net/libpcap && make install"; \
	  false)
