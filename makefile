
elf-surgeon: elf-surgeon.c err.h proto.h struct.h makefile
	gcc -ggdb $< -o $@


explore: explore.c
	gcc $< -o $@
