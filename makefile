explore: explore.c
	gcc $< -o $@

global-func: global-func.c err.h
	gcc $< -o $@