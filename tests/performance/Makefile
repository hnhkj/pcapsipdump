LIBS ?= -lpcap -lstdc++

tests: calltable_benchmark

calltable_benchmark: calltable_benchmark.cpp ../../calltable.cpp ../../calltable.h
	$(CXX) $(CXXFLAGS) -std=c++11 $(LDFLAGS) $(DEFS) $(BSDSTR_DEFS) -ggdb -pg \
	calltable_benchmark.cpp ../../calltable.cpp $(LIBS) $(BSDSTR_LIBS) \
	-o calltable_benchmark
