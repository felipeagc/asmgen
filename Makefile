all: asmgen test generated

asmgen: main.c
	gcc -g -Wall $< -o $@

test: test.o
	gcc -no-pie $< -o $@

test.o: test.s
	nasm -f elf64 $< -o $@

generated.s: asmgen
	./asmgen > generated.s

generated.o: generated.s
	nasm -f elf64 $< -o $@

other.o: other.c
	gcc -no-pie -c $< -o $@

generated: generated.o other.o
	gcc -no-pie -o $@ $^

clean: .PHONY
	rm asmgen
	rm test
	rm test.o

.PHONY:
