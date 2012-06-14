#include <stdio.h>
#include <elf.h>
#include <stdlib.h>

/*static*/ int analyze(FILE * fp);
static void show_section_header_table(FILE * fp, Elf32_Ehdr * elf_header);
static void read_string_table(FILE * fp, Elf32_Ehdr * elf_header);
static char * string_table;

#define sek(fp, pos)  fseek(fp, pos, SEEK_SET)
#define notz(expr, msg, ...)      \
  if (!(expr)) {  \
       printf("file '%s'; func '%s'; line %d:\ncode: %s\nmessage: ", \
              __FILE__, __func__, __LINE__, #expr); \
       printf(msg, ##__VA_ARGS__);                                    \
       exit(1); }

#define ntz(expr, msg)      \
  if (!(expr)) {  \
       printf("file '%s'; func '%s'; line %d:\ncode: %s\nmessage: %s\n", \
              __FILE__, __func__, __LINE__, #expr, msg); \
       exit(1); }

#define oops(expect, expr, msg, ...)                \
  { \
     int __got = (expr); \
     if ((expect) != __got) { \
       printf("file '%s'; func '%s'; line %d: expected %d but got %d\ncode: %s\nmessage: ", \
              __FILE__, __func__, __LINE__, expect, __got, #expr); \
       printf(msg, ##__VA_ARGS__);                                    \
       exit(1); } }

#define ops(expect, expr, msg) \
  { \
     int __got = (expr); \
     if ((expect) != __got) { \
       printf("file '%s'; func '%s'; line %d: expected %d but got %d\ncode: %s\nmessage: %s\n", \
              __FILE__, __func__, __LINE__, expect, __got, #expr, msg);  \
       exit(1); } }

int main(int argc, char ** argv) {
  FILE * fp;  
  notz(argc == 2, "usage: %s <path-to-file>\n", argv[0]);
  notz(fp = fopen(argv[1], "rb"), "cannot open file '%s'\n", argv[1]);
  return analyze(fp);
}

/*static*/ int analyze(FILE * fp) {
  Elf32_Ehdr elf_header;
  int  size_section_header_entry;

  ops(1, fread(&elf_header, sizeof(elf_header), 1, fp), "cannot read elf_header");

  printf("section header table = %x\nnum entries = %d\nent size = %d\n",
         elf_header.e_shoff, elf_header.e_shnum, elf_header.e_shentsize);
  ntz(!sek(fp, elf_header.e_shoff), "cannot seek to section-header-table");
  read_string_table(fp, &elf_header);
  ntz(!sek(fp, elf_header.e_shoff), "cannot seek to section-header-table");  
  show_section_header_table(fp, &elf_header);
}

static void read_string_table(FILE * fp, Elf32_Ehdr * elf_header) {
  Elf32_Shdr tblnames;
  int ofs = elf_header->e_shoff + elf_header->e_shentsize * elf_header->e_shstrndx;
  notz(!sek(fp, ofs),
       "ofs = %d\n", ofs);
  oops(1, fread(&tblnames, sizeof(tblnames), 1, fp),
       "ofs = %d;  e_shoff = %d; e_shentsize = %d; shstrndx = %d\n",
       ofs, elf_header->e_shoff, elf_header->e_shentsize, elf_header->e_shstrndx);

  notz(string_table = (char*) malloc(tblnames.sh_size), "need memory %d\n", tblnames.sh_size);

  ntz(!sek(fp, tblnames.sh_offset), "");
  
  ops(1, fread(string_table, tblnames.sh_size, 1, fp), "");
}

static void show_section_header_table(FILE * fp, Elf32_Ehdr * elf_header) {
  int i = 0;
  Elf32_Shdr header;
  long ipos = ftell(fp);
  
  for (; i < elf_header->e_shnum; ++i) {
    sek(fp, ipos + i * elf_header->e_shentsize);
    ops(1, fread(&header, sizeof(header), 1, fp), "cannot read section header entry");

    printf("%d) section ofs = %x;\n", i, header.sh_offset);
    if (header.sh_name) {
      char * name = string_table + header.sh_name;
      printf("section name = %s\n", name);
    }
    switch (header.sh_type) {
    case SHT_DYNSYM:
      printf("dynsym table\n");            
      break;
    case SHT_DYNAMIC:
      printf("dynamic table\n");      
      break;
    case SHT_SYMTAB:
      printf("sym table\n");
      break;
    default:
      break;
    }
  }
}
