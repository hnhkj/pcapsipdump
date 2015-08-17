CHECK_LIBBSD = $(CXX) $(CXXFLAGS) $(LDFLAGS) make-checks/libbsd.cpp -lbsd -o make-checks/libbsd 2>/dev/null

make-checks/libbsd:
	@$(CHECK_LIBBSD) || (\
	  echo; \
	  echo $(CHECK_LIBBSD); \
	  echo; \
	  echo "==="; \
	  echo "Warning: recommended library not found: libbsd (BSD string library) "; \
	  echo "Consider installing it in your distribution-specific manner, e.g.:"; \
	  echo " yum install libbsd-devel"; \
	  echo " apt-get install libbsd-dev"; \
	  echo "==="; \
	  true)
