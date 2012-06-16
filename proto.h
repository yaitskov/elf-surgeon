#ifndef __PROTO_H__
#define __PROTO_H__

void help(Ctx * ctx);
Command * find_command(Command * cmds, int argc, const char ** argv);
void prepare_ctx(Ctx * ctx, Command * toDo);
void set_func_size(Ctx * ctx);
void global_func(Ctx * ctx);

Elf32_Ehdr * load_elf_header(FILE * fp);
const char * read_string_table(FILE * fp, Elf32_Ehdr * elf_header);
void read_dynamic_strings(Ctx * ctx);
Section * get_section_by_id(Ctx * ctx, const int id);
const char * get_entry_name(Section * section, SectionEntry * entry);
Section * find_section_by_type(Ctx * ctx, const int type);
Segment * find_segment_by_type(Ctx * ctx, const int type);
SectionEntry * find_entry_by_name(Section * section, const char * name);
void save_entry(Ctx * ctx, SectionEntry * entry);
const char * find_param(int argc, const char * name, const char ** argv);
void copy_file(FILE * in, FILE * out);
void elf_load(Ctx * ctx);
int find_int_param(int argc, const char * name, const char ** argv);



#define sek(fp, pos)  fseek(fp, pos, SEEK_SET)

#endif
