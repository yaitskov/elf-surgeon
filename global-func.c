#include <stdio.h>
#include <elf.h>
#include <stdlib.h>
#include "err.h"

typedef struct {
  const char * lfunc;
  const char * in_fname;
  const char * victim_func;
  const char * out_fname;
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
  
void  globalize_local_func(Ctx * ctx);
Elf32_Ehdr * load_elf_header(FILE * fp);
const char * read_string_table(FILE * fp, Elf32_Ehdr * elf_header);
void read_dynamic_strings(Ctx * ctx);
Section * get_section_by_id(Ctx * ctx, const int id);
const char * get_entry_name(Section * section, SectionEntry * entry);
Section * find_section_by_type(Ctx * ctx, const int type);
Segment * find_segment_by_type(Ctx * ctx, const int type);
SectionEntry * find_entry_by_name(Section * section, const char * name);
void save_entry(Ctx * ctx, SectionEntry * entry);

#define sek(fp, pos)  fseek(fp, pos, SEEK_SET)

int main(int argc, char ** argv) {
  FILE * fp;
  notz(argc == 5,
       "usage: %s <lfunc> <victim-func> <path-to-orig-file> <path-to-out-file>\n",
       argv[0]);
  notz(fp = fopen(argv[3], "rb"), "file '%s'\n", argv[3]);  
  {
    Ctx ctx = { .out_fname = argv[4], .lfunc = argv[1],
                .f_in = fp, .victim_func = argv[2], .in_fname = argv[3] };
    const int sz = 100;
    char buf[sz];
    int read;
    notz(ctx.f_out = fopen(argv[4], "wb"), "file '%s'\n", argv[4]);
    while ((read = fread(buf, 1, sz, ctx.f_in))) {
      fwrite(buf, read, 1, ctx.f_out);
    }
    globalize_local_func(&ctx);
    fclose(ctx.f_out);
    fclose(ctx.f_in);
  }
  return 0;
}

void globalize_local_func(Ctx * ctx) {
  Section * symtab, * dynsym;

  SectionEntry * lfunc_entry, * victim_stab, * victim_dyn;
  nz(ctx->elf_header = load_elf_header(ctx->f_in));

  ctx->string_table = read_string_table(ctx->f_in, ctx->elf_header);
  read_dynamic_strings(ctx);
  
  notz(symtab = find_section_by_type(ctx, SHT_SYMTAB),
       "file '%s' doesn't have symbol table section\n", ctx->in_fname);
  notz(dynsym = find_section_by_type(ctx, SHT_DYNSYM),
       "file '%s' doesn't have symbol table section\n", ctx->in_fname);
  
  notz(lfunc_entry = find_entry_by_name(symtab, ctx->lfunc),
       "symtab section doesn't have symbol '%s'\n",  ctx->lfunc);
  notz(victim_stab = find_entry_by_name(dynsym, ctx->victim_func),
       "dynsym section doesn't have symbol '%s'\n",  ctx->victim_func);
  notz(victim_dyn = find_entry_by_name(symtab, ctx->victim_func),
       "symtab section doesn't have symbol '%s'\n",  ctx->victim_func);       
  
  victim_stab->sym.st_size = lfunc_entry->sym.st_size;
  victim_stab->sym.st_value = lfunc_entry->sym.st_value;
  //victim_stab->sym.st_alue = lfunc_entry->sym.st_value;
  /* lfunc_entry->sym.st_size = victim_dyn->sym.st_size; */
  /* lfunc_entry->sym.st_value = victim_dyn->sym.st_value; */

  victim_dyn->sym.st_size = victim_stab->sym.st_size;
  victim_dyn->sym.st_value = victim_stab->sym.st_value;
  
  save_entry(ctx, victim_dyn);
  save_entry(ctx, victim_stab);
  //save_entry(lfunc_entry);  
}

Elf32_Ehdr * load_elf_header(FILE * fp) {
  nz(!sek(fp, 0));
  Elf32_Ehdr * elf_header = (Elf32_Ehdr*)malloc(sizeof(Elf32_Ehdr));
  ops(1, fread(elf_header, sizeof(Elf32_Ehdr), 1, fp), "");

  printf("section header table = %x\nnum entries = %d\nent size = %d\n",
         elf_header->e_shoff, elf_header->e_shnum, elf_header->e_shentsize);
  return elf_header;
}

const char * read_string_table(FILE * fp, Elf32_Ehdr * elf_header) {
  Elf32_Shdr tblnames;
  char * string_table;
  int ofs = elf_header->e_shoff + elf_header->e_shentsize * elf_header->e_shstrndx;
  notz(!sek(fp, ofs), "ofs = %d\n", ofs);
  oops(1, fread(&tblnames, sizeof(tblnames), 1, fp),
       "ofs = %d;  e_shoff = %d; e_shentsize = %d; shstrndx = %d\n",
       ofs, elf_header->e_shoff, elf_header->e_shentsize, elf_header->e_shstrndx);

  notz(string_table = (char*) malloc(tblnames.sh_size), "need memory %d\n", tblnames.sh_size);
  nz(!sek(fp, tblnames.sh_offset));  
  ops(1, fread(string_table, tblnames.sh_size, 1, fp), "");
  return string_table;
}

void read_dynamic_strings(Ctx * ctx) {
  Segment * dynamic, * load;
  Elf32_Dyn dyn;  
  int loadaddr;
  unsigned long str_tab_len;
  unsigned long offset;
  notz(load = find_segment_by_type(ctx, PT_LOAD),
       "file '%s' doesn't have dynamic segment.\n", ctx->in_fname);
  // dynamic_addr = segment->p_offset;
  // dynamic_size = segment->p_filesz; in bytes
  notz(dynamic = find_segment_by_type(ctx, PT_DYNAMIC),
       "file '%s' doesn't have dynamic segment. foad.\n", ctx->in_fname);

  loadaddr = (load->header.p_vaddr & 0xfffff000) - (load->header.p_offset & 0xfffff000);

  nz(!sek(ctx->f_in, dynamic->header.p_offset));

  while (1) {
    ops(1, fread(&dyn, sizeof(dyn), 1, ctx->f_in), "");
    ntz(dyn.d_tag - DT_NULL, "symtable isn't in dynamic segment");
    if (dyn.d_tag == DT_STRTAB) {
      offset = dyn.d_un.d_val - loadaddr;
      nz(!fseek(ctx->f_in, 0, SEEK_END));
      str_tab_len = ftell(ctx->f_in) - offset;
      nz(str_tab_len > 0);
      free(dynamic);
      free(load);
      nz(ctx->dynamic_strings = (char*)malloc(str_tab_len));
      nz(!sek(ctx->f_in, offset));
      ops(1, fread(ctx->dynamic_strings, str_tab_len, 1, ctx->f_in), "");
      return;
    }
  }  
}

Section * get_section_by_id(Ctx * ctx, const int id) {
  Section * s;
  int ofs;
  nz(s = (Section*)malloc(sizeof(Section)));
  nz(ctx->elf_header->e_shnum > id);
  ofs = id * ctx->elf_header->e_shentsize;
  nz(!sek(ctx->f_in, ctx->elf_header->e_shoff + ofs));
  ops(1, fread(&s->header, sizeof(s->header), 1, ctx->f_in), "");
  return s;  
}

const char * get_entry_name(Section * section, SectionEntry * entry) {
  if (!entry->sym.st_name)
    return 0;
  if (section->header.sh_link == section->ctx->elf_header->e_shstrndx) {
    return section->ctx->string_table + entry->sym.st_name;
  }
  if (!section->names) {
    Section * names_section = get_section_by_id(section->ctx, section->header.sh_link);
    
    nz(section->names = (char*)malloc(names_section->header.sh_size));
    nz(!sek(section->ctx->f_in, names_section->header.sh_offset));
    ops(1, fread(section->names, names_section->header.sh_size, 1, section->ctx->f_in), "");
  }
  return section->names + entry->sym.st_name;
}
      
Section * find_section_by_type(Ctx * ctx, const int type) {
  Section * s;  
  int i;
  nz(s = (Section*)malloc(sizeof(Section)));
  s->names = 0;
  s->ctx = ctx;
  for (i = 0; i < ctx->elf_header->e_shnum; ++i) {
    int ofs = i * ctx->elf_header->e_shentsize;
    nz(!sek(ctx->f_in, ctx->elf_header->e_shoff + ofs));
    ops(1, fread(&s->header, sizeof(s->header), 1, ctx->f_in), "");
    if (type == s->header.sh_type) 
      return s;
  }
  free(s);
  return 0;
}

Segment * find_segment_by_type(Ctx * ctx, const int type) {
  Segment * s;
  int i; 
  nz(s = (Segment*)malloc(sizeof(Segment)));
  s->ctx = ctx;
  for (i = 0; i < ctx->elf_header->e_phnum; ++i) {
    int ofs = i * ctx->elf_header->e_phentsize;
    nz(!sek(ctx->f_in, ctx->elf_header->e_phoff + ofs));
    ops(1, fread(&s->header, sizeof(s->header), 1, ctx->f_in), "");
    if (type == s->header.p_type) 
      return s;    
  }
  free(s);
  return 0;
}

SectionEntry * find_entry_by_name(Section * section, const char * name) {
  SectionEntry * se;  
  int i;
  const char * ent_name;
  nz(se = (SectionEntry*)malloc(sizeof(SectionEntry)));
  for (i = 0; i < section->header.sh_size; i += section->header.sh_entsize) {
    nz(!sek(section->ctx->f_in, section->header.sh_offset + i));    
    ops(1, fread(&se->sym, sizeof(se->sym), 1, section->ctx->f_in), "");
    //TODO: name for entry
    ent_name = get_entry_name(section, se);
    if (!ent_name)
      continue;
    //printf("entry '%s'\n", ent_name);
    if (!strcmp(ent_name, name)) {
      printf("found entry %p  ofs = %d\n", se, section->header.sh_offset + i);
      se->ofs = section->header.sh_offset + i;
      return se;
    }
  }
  free(se);
  return 0;
}

void save_entry(Ctx * ctx, SectionEntry * entry) {
  printf("save entry %p with ofs = %ld\n", entry, entry->ofs);
  nz(!sek(ctx->f_out, entry->ofs));
  oops(1,fwrite(&entry->sym, sizeof(entry->sym), 1, ctx->f_out),
       "cannot save entry '%s'\n",
       entry->sym.st_name + ctx->string_table);
}

