CXX=g++
FLGS=-g -std=c++0x -DBN_DEBUG -pthread -ldl -lcrypto -lssl -lgmpxx -lgmp
SRCS=$(shell ls *.cpp) $(shell ls net/*.cpp) $(shell ls crypt/*.cpp) $(shell ls prot/*.cpp) $(shell ls mac/*.cpp) $(shell ls test/*.cpp)
OBJS=$(subst .cpp,.o,$(SRCS))

sshay: $(OBJS)
	$(CXX) -o sshay $(OBJS) $(FLGS)

%.o: %.cpp
	$(CXX) -o $@ -c $< $(FLGS)

clean:
	@echo Cleaning up my shits...
	@rm $(OBJS)
	@echo Done!
