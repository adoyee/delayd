
CXX=g++

CXXFLAGS=-O3 -std=c++11 -c

LDPATH=/usr/local/lib

all:delayd

delayd:main.o net.o
	$(CXX) main.o net.o -L$(LDPATH) -l tins -o delayd
main.o:main.cpp net.h
	$(CXX) $(CXXFLAGS) main.cpp -o main.o
net.o: net.cpp net.h
	$(CXX) $(CXXFLAGS) net.cpp -o net.o
clean:
	- rm *.o delayd
