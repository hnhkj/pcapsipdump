check-cpp:
	@$(CC) $(CPPFLAGS) $(LDFLAGS) -lstdc++ make-checks/check_cpp.cpp -o /dev/null || (\
	  echo; \
	  echo "C++ compiler and/or standard libraries not found."; \
	  echo "Please install them in your distribution-specific manner, e.g.:"; \
	  echo " yum install gcc-c++ libstdc++-devel"; \
	  echo " apt-get install gcc-c++ libstdc++-devel"; \
	  false)
