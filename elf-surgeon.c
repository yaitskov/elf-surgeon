/* elf-surgeon: Copyright (C) 2012 by Daneel S. Yaitskov <rtfm.rtfm.rtfm@gmail.com>
 * License GPLv2: GNU GPL version 2.
 * This is free software; you are free to change and redistribute it.
 * There is NO WARRANTY, to the extent permitted by law.
 */
#include <stdio.h>
#include <elf.h>
#include <stdlib.h>
#include "err.h"
#include "struct.h"
#include "proto.h"

int main(int argc, const char ** argv) {
  FILE * fp;
  Command * toDo;
  Ctx ctx = { .argc = argc,
              .argv = argv,
              .f_out = 0,
              .f_in = 0,
              .commands = (Command [])
              {    { .name = "help",
                     .code = help,  .flags = 0,
                     .help = (const char *[]){ "", "print list available commands", 0} },
                   { .name = "set-func-size", .code = set_func_size,
                     .flags = FUNC_SIZE | VICTIM_FUNC | IO_FILES,
                     .help = (const char *[]){ "-v <func-name> -s <num-in-bytes> -i <input-elf> -o <out-elf> ",
                                 "set arbitary size of function", 0 } },
                   { .name = "global-func", .code = global_func,
                     .flags = LOCAL_FUNC | VICTIM_FUNC | IO_FILES,
                     .help = (const char *[]){ "-v <global-func> -l <local-func> "
                               "-i <input-elf> -o <out-elf> ",
                               "copy address and size of local func to global one", 0 } },
                   { .name = 0 }
              }
  };
  check_input(argc > 1,
              "usage: %s <command> ...\n"
              "usage: %s help   to get list of available commands\n",
              argv[0], argv[0]);

  check_input(toDo = find_command(ctx.commands, argc, argv),
              "command '%s' not found\n", argv[1]);
  prepare_ctx(&ctx, toDo);
  toDo->code(&ctx);  
  if (ctx.f_out) {
    const char * fname = find_param(argc, "-o", argv + 2);
    FILE * fres;
    nz(!sek(ctx.f_out, 0));    
    check_input(fres = fopen(fname, "wb"),
                "cannot write results into file '%s'\n", fname);
    copy_file(ctx.f_out, fres);
    fclose(fres);
    fclose(ctx.f_out);
  }
  if (ctx.f_in)  fclose(ctx.f_in);
  return 0;
}

void help(Ctx * ctx) {
  Command * cmd = ctx->commands;
  printf("list of commands:\n");
  for (; cmd->name; ++cmd) {
    const char ** h = cmd->help;
    printf("%15s  %s\n", cmd->name, *h ? *h : "");
    while (*++h) 
      printf("%15s  %s\n", "", *h);
  }
  printf("\nAuthor: Daneel S. Yaitskv <rtfm.rtfm.rtfm@gmail.com>\n");
}

Command * find_command(Command * cmds, int argc, const char ** argv) {
  const char * cmd_name = argv[1];
  while (cmds->name) {
    if (!strcmp(cmd_name, cmds->name))
      return cmds;
    ++cmds;
  }
}

/**
 * open input and output files if required
 */
void prepare_ctx(Ctx * ctx, Command * toDo) {
  int i;
  if (toDo->flags & OUTPUT_FILE) {
    const char * fname = find_param(ctx->argc, "-o", ctx->argv + 2);
    check_input(fname,
                "command '%s' required argument '-o' <file> for output file\n",
                toDo->name);
    // intermediate tmp file cause input and output file can be the same
    // changing output file may make them unreadable temporally
    notz(ctx->f_out = tmpfile(),
         "cannot create tmp file for writing changed file '%s'\n", fname);    
  }
  if (toDo->flags & INPUT_FILE) {
    const char * fname = find_param(ctx->argc, "-i", ctx->argv + 2);
    check_input(fname,
                "command '%s' required argument '-i' <file> for input file\n",
                toDo->name);
    check_input(ctx->f_in = fopen(fname, "rb"),
                "cannot open file '%s' for reading\n", fname);      
  }
  if (toDo->flags & (INPUT_FILE | OUTPUT_FILE) == (INPUT_FILE | OUTPUT_FILE))
    copy_file(ctx->f_in, ctx->f_out);
  if (toDo->flags & VICTIM_FUNC)
    check_input(find_param(ctx->argc, "-v", ctx->argv + 2),
                "name of victim function is required. argument is '-v'\n");
  if (toDo->flags & LOCAL_FUNC)
    check_input(find_param(ctx->argc, "-l", ctx->argv + 2),
                "name of local function is required. argument is '-l'\n");    
  if (toDo->flags & FUNC_SIZE) {
    const char * size = find_param(ctx->argc, "-s", ctx->argv + 2);
    unsigned int sz = 0;
    check_input(size,  "size is required. argument is '-s'\n");
    check_input(sscanf(size, "%u", &sz), "'-s' argument takes only nonegative  integers\n");
  }
}

void set_func_size(Ctx * ctx) {
  Section * symtab, * dynsym;
  int new_func_size = find_int_param(ctx->argc, "-s", ctx->argv);
  SectionEntry * victim_ent;
  const char * in_fname =     find_param(ctx->argc, "-i", ctx->argv + 2);
  const char * victim_func =  find_param(ctx->argc, "-v", ctx->argv + 2);
  
  elf_load(ctx);  
  check_input(symtab = find_section_by_type(ctx, SHT_SYMTAB),
              "file '%s' doesn't have symtab section\n", in_fname);
  info_user(dynsym = find_section_by_type(ctx, SHT_DYNSYM),
            "file '%s' doesn't have dynsym section\n", in_fname);

  if (dynsym) {   // optional if local func  
    victim_ent = find_entry_by_name(dynsym, victim_func);
    if (victim_ent) {
      victim_ent->sym.st_size = new_func_size;
      save_entry(ctx, victim_ent);
    }
  }
  check_input(victim_ent = find_entry_by_name(symtab, victim_func),
              "symtab section doesn't have symbol '%s'\n",  victim_func);
  victim_ent->sym.st_size = new_func_size;  
  save_entry(ctx, victim_ent);  
}

void global_func(Ctx * ctx) {
  Section * symtab, * dynsym;

  SectionEntry * lfunc_entry, * victim_stab, * victim_dyn;
  const char * in_fname =     find_param(ctx->argc, "-i", ctx->argv + 2);
  const char * lfunc =        find_param(ctx->argc, "-l", ctx->argv + 2);
  const char * victim_func =  find_param(ctx->argc, "-v", ctx->argv + 2); 

  elf_load(ctx);
  
  check_input(symtab = find_section_by_type(ctx, SHT_SYMTAB),
              "file '%s' doesn't have symbol table section\n", in_fname);
  check_input(dynsym = find_section_by_type(ctx, SHT_DYNSYM),
              "file '%s' doesn't have symbol table section\n", in_fname);
  
  notz(lfunc_entry = find_entry_by_name(symtab, lfunc),
       "symtab section doesn't have symbol '%s'\n",  lfunc);
  notz(victim_stab = find_entry_by_name(dynsym, victim_func),
       "dynsym section doesn't have symbol '%s'\n",  victim_func);
  notz(victim_dyn = find_entry_by_name(symtab, victim_func),
       "symtab section doesn't have symbol '%s'\n",  victim_func);       
  
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
  const char * in_fname =     find_param(ctx->argc, "-i", ctx->argv + 2);  
  notz(load = find_segment_by_type(ctx, PT_LOAD),
       "file '%s' doesn't have dynamic segment.\n", in_fname);
  // dynamic_addr = segment->p_offset;
  // dynamic_size = segment->p_filesz; in bytes
  notz(dynamic = find_segment_by_type(ctx, PT_DYNAMIC),
       "file '%s' doesn't have dynamic segment. foad.\n", in_fname);

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

const char * find_param(int argc, const char * name, const char ** argv) {
  int i = 0;
  for (; i < argc; ++i)
    if (!strcmp(name, argv[i]) && i + 1 < argc) 
      return argv[i+1];
  return 0;
}

void copy_file(FILE * in, FILE * out) {
  char buf[1024];
  int read;
  nz(in);  nz(out);
  while ((read = fread(buf, 1, sizeof(buf), in))) {
    ops(read, fwrite(buf, 1, read, out), "");
  }
}

void elf_load(Ctx * ctx) {
  nz(ctx->f_in);
  nz(ctx->elf_header = load_elf_header(ctx->f_in));

  ctx->string_table = read_string_table(ctx->f_in, ctx->elf_header);
  read_dynamic_strings(ctx);  
}

int find_int_param(int argc, const char * name, const char ** argv) {
  const char * val = find_param(argc, name, argv);
  unsigned int result;
  nz(val);
  nz(sscanf(val, "%u", &result));
  return result;  
}
