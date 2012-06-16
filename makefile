

elf-surgeon: elf-surgeon.c err.h proto.h struct.h makefile
	gcc -ggdb $< -o $@

install: elf-surgeon
	cp $^ /usr/bin/

explore: explore.c
	gcc $< -o $@

clean:
	rm -rf makefile *.o elf-surgeon