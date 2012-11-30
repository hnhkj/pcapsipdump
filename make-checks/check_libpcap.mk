check-libpcap:
	@$(CC) $(CPPFLAGS) $(LDFLAGS) -lpcap make-checks/check_libpcap.c -o /dev/null || (\
	  echo; \
	  echo "Required library not found: pcap "; \
	  echo "Please install it in your distribution-specific manner, e.g.:"; \
	  echo " yum install libpcap libpcap-devel"; \
	  echo " apt-get install libpcap libpcap-dev"; \
	  echo " cd ~ports/net/libpcap && make install"; \
	  false)
