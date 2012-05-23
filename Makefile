main: *.o
	gcc -g -O2 main.o -lev -L/usr/local/lib -o main
main.o: *.c *.h Makefile
	gcc -g -O2 -c -o main.o main.c
.PHONY: clean
clean:
	rm *.o main

