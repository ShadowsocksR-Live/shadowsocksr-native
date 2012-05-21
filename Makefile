main: main.o
	gcc -g -O2 main.o -lev -L/usr/local/lib -o main
main.o: main.c
	gcc -g -O2 -c -o main.o main.c
.PHONY: clean
clean:
	rm *.o main

