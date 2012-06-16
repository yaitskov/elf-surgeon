
global-func: global-func.c err.h proto.h struct.h makefile
	gcc -ggdb $< -o $@


explore: explore.c
	gcc $< -o $@
