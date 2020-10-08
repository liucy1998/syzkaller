all: ./strace/Makefile strace libsclog.a sclog_test

./strace/Makefile: ./strace/Makefile.am ./strace/bootstrap ./strace/configure.ac 
	cd ./strace && ./bootstrap && ./configure
	
libsclog.a: ./strace/libsclog.a 
	cp ./strace/libsclog.a ./

./sclog_test: sclog_test.c sclog.h libsclog.a
	cc sclog_test.c libsclog.a -lrt -o sclog_test

.PHONY: test clean strace

# force execution
strace: 
	make -C ./strace

test: ./sclog_test
	./sclog_test

clean:
	rm ./sclog_test
