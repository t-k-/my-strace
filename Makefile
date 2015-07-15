all: my-strace

my-strace: main.c
	gcc $< -o $@

clean:
	rm -f my-strace
