CC     = gcc
CPP     = g++
RM     = rm -f

.PHONY: all clean

all: pmctest

clean:
	$(RM) pmctest *.o

%: %.o
	$(CC) -o $@ $^ $(LIBS)

pmctest: PMCTestA.o PMCTestB.o
	$(CPP) -g -m64 -o pmctest PMCTestA.o PMCTestB.o -lpthread

PMCTestA.o: PMCTestA.cpp
	$(CPP) -g -c -m64 -o PMCTestA.o PMCTestA.cpp -lpthread

PMCTestB.o: PMCTestB.cpp
	$(CPP) -g -c -m64 -o PMCTestB.o PMCTestB.cpp -lpthread

%.o: %.c
	$(CC) $(CFLAGS) -c  $<
