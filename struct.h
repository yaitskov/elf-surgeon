#ifndef __STRUCT_H__
#define __STRUCT_H__
struct _Command;

typedef struct {
  int argc;
  struct _Command * commands;
  const char ** argv;  
  FILE * f_in;
  const char * string_table;
  char * dynamic_strings;
  FILE * f_out;
  Elf32_Ehdr * elf_header;
} Ctx;

typedef struct {
  Ctx * ctx;
  Elf32_Shdr   header;
  Elf32_Sym  * body;
  char       * names;
  int          len; // num items in body
} Section;

typedef struct {
  Ctx * ctx;
  Elf32_Phdr   header;
} Segment;

typedef struct {
  long         ofs;   // offset from start of file to  Elf32_Sym
  Elf32_Sym    sym;
} SectionEntry;

struct _Command {
  const char * name;
  const char ** help;
#define INPUT_FILE  1   // -i <file> required
#define OUTPUT_FILE 2   // -o <file> required
#define IO_FILES  (OUTPUT_FILE | INPUT_FILE)
#define VICTIM_FUNC 4   // -v <func> requried
#define LOCAL_FUNC  8   // -l <func> required
#define FUNC_SIZE   16  // -s <num-in-bytes> required
  int flags;
  void (*code)(Ctx * ctx);
};

typedef struct _Command Command;
#endif
