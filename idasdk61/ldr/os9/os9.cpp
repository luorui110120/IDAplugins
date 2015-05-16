/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov <ig@datarescue.com>
 *      ALL RIGHTS RESERVED.
 *
 *      This file is able to load:
 *              - OS9 object files
 *              - FLEX STX files
 *      for 6809
 *
 */

#include "../idaldr.h"
#include "os9.hpp"

//----------------------------------------------------------------------
static void swap_os9_header(os9_header_t &h)
{
#if __MF__
  qnotused(h);
#else
  h.magic   = swap16(h.magic);
  h.size    = swap16(h.size);
  h.name    = swap16(h.name);
  h.start   = swap16(h.start);
  h.storage = swap16(h.storage);
#endif
}

//----------------------------------------------------------------------
// calc header parity
static uchar calc_os9_parity(os9_header_t &h)
{
  uchar *ptr = (uchar *)&h;
  int parity = 0;
  for ( int i=0; i < 8; i++ ) parity ^= *ptr++;
  return (uchar)~parity;
}

//----------------------------------------------------------------------
static const char object_name[] = "OS9 object file for 6809";
static bool is_os9_object_file(linput_t *li, char *fileformatname)
{
  os9_header_t h;
  qlseek(li, 0);
  if ( qlread(li,&h,sizeof(os9_header_t)) != sizeof(os9_header_t) ) return false;
  swap_os9_header(h);
  if ( h.magic == OS9_MAGIC
    && calc_os9_parity(h) == h.parity
    && (h.type_lang & OS9_LANG) == OS9_LANG_OBJ )
  {
    qstrncpy(fileformatname, object_name, MAX_FILE_FORMAT_NAME);
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
static const char flex_name[] = "FLEX STX file";
static bool is_os9_flex_file(linput_t *li, char *fileformatname)
{
  qlseek(li, 0);
  int32 fsize = qlsize(li);
  int c;
  int nrec2 = 0;
  int fpos = 0;
  while ( 1 )
  {
    if ( fpos > fsize ) return false;
    qlseek(li, fpos, SEEK_SET);
    if ( (c=qlgetc(li)) == EOF ) break;
    if ( fpos == 0 && c != 0x2 ) return false;  // the first byte must be 0x2
    switch ( c )
    {
      case 0:
        fpos++;
        break;
      case 0x2:
        {
          c = qlgetc(li);
          int adr = (c<<8) | qlgetc(li);
          if ( adr == EOF ) return false;
          c = qlgetc(li);        // number of bytes
          if ( c == 0 ) return false;
          fpos += c+4;
          nrec2++;
        }
        break;
      case 0x16:
        fpos += 3;
        break;
      default:
        return false;
    }
  }
  if ( nrec2 == 0 ) return false;
  qstrncpy(fileformatname, flex_name, MAX_FILE_FORMAT_NAME);
  return true;
}

//----------------------------------------------------------------------
int idaapi accept_file(linput_t *li,char fileformatname[MAX_FILE_FORMAT_NAME],int n)
{
  if ( n != 0 ) return 0;       // reject repeated calls
  return is_os9_object_file(li,fileformatname)          // test for OS9
      || is_os9_flex_file(li,fileformatname);           // test for FLEX
}

//----------------------------------------------------------------------
static const char *get_os9_type_name(uchar type)
{
  switch ( type )
  {
    case OS9_TYPE_ILL: return "illegal";
    case OS9_TYPE_PRG: return "Program module";
    case OS9_TYPE_SUB: return "Subroutine module";
    case OS9_TYPE_MUL: return "Multi-Module (for future use)";
    case OS9_TYPE_DAT: return "Data module";
    case OS9_TYPE_SYS: return "OS-9 System Module";
    case OS9_TYPE_FIL: return "OS-9 File Manager Module";
    case OS9_TYPE_DRV: return "OS-9 Device Driver Module";
    case OS9_TYPE_DDM: return "OS-9 Device Descriptor Module";
    default:           return "unknown";
  }
}

//----------------------------------------------------------------------
static const char *get_os9_lang_name(uchar lang)
{
  switch ( lang )
  {
    case OS9_LANG_DAT: return "Data (not executable)";
    case OS9_LANG_OBJ: return "6809 object code";
    case OS9_LANG_BAS: return "BASIC09 I-Code";
    case OS9_LANG_PAS: return "PASCAL P-Code";
    case OS9_LANG_C  : return "C I-Code";
    case OS9_LANG_CBL: return "COBOL I-Code";
    case OS9_LANG_FTN: return "FORTRAN I-Code";
    default:           return "unknown";
  }
}

//----------------------------------------------------------------------
#define LOADING_OFFSET 0x1000

void load_obj_file(linput_t *li)
{
  os9_header_t h;
  qlseek(li,0);
  lread(li,&h,sizeof(os9_header_t));
  swap_os9_header(h);

  if ( ph.id != PLFM_6800 )
    set_processor_type("6809", SETPROC_ALL|SETPROC_FATAL);
  set_target_assembler(5);

  ea_t start = toEA(inf.baseaddr, LOADING_OFFSET);
  ea_t end   = start + h.size;

  file2base(li, 0, start, end, FILEREG_PATCHABLE);
  add_segm(inf.baseaddr,  start, start + h.size, "TEXT", "CODE");

  create_filename_cmt();
  ea_t ea = start;
           set_name(ea, "magic");      doWord(ea, 2); op_num(ea,0);
  ea += 2; set_name(ea, "size");       doWord(ea, 2); op_num(ea,0);
  ea += 2; set_name(ea, "name");       doWord(ea, 2); if ( h.name < h.size ) set_offset(ea,0, start);
  ea += 2; set_name(ea, "type_lang");  doByte(ea, 1); op_num(ea,0);
           append_cmt(ea, get_os9_type_name(h.type_lang & OS9_TYPE), 0);
           append_cmt(ea, get_os9_lang_name(h.type_lang & OS9_LANG), 0);
  ea += 1; set_name(ea, "attrib");     doByte(ea, 1); op_num(ea,0);
           if ( h.attrib & OS9_SHARED ) append_cmt(ea, "Shared module", 0);
  ea += 1; set_name(ea, "parity");     doByte(ea, 1); op_num(ea,0);
  ea += 1; set_name(ea, "start_ptr");  doWord(ea, 2); set_offset(ea,0, start);
  ea += 2; set_name(ea, "storage");    doWord(ea, 2); op_num(ea,0);
  inf.startIP  = LOADING_OFFSET + h.start;
  inf.start_cs = inf.baseaddr;
}

//----------------------------------------------------------------------
void load_flex_file(linput_t *li)
{
  qlseek(li,0);

  if ( ph.id != PLFM_6800 )
    set_processor_type("6809", SETPROC_ALL|SETPROC_FATAL);
  set_target_assembler(5);

  int c;
  ea_t bottom = BADADDR;
  ea_t top = 0;
  while ( 1 )
  {
    if ( (c=qlgetc(li)) == EOF ) break;
    switch ( c )
    {
      case 0:
        break;
      case 0x2:
        {
          c = qlgetc(li);
          int adr = (c<<8) | qlgetc(li);
          c = qlgetc(li);        // number of bytes
          ea_t start = toEA(inf.baseaddr, adr);
          ea_t end   = start + c;
          file2base(li, qltell(li), start, end, FILEREG_PATCHABLE);
          if ( bottom > start ) bottom = start;
          if ( top    < end   ) top    = end;
        }
        break;
      case 0x16:
        c = qlgetc(li);
        inf.startIP  = (c<<8) | qlgetc(li);
        inf.start_cs = inf.baseaddr;
        break;
      default:
        error("internal error in os9 loader");
    }
  }
  add_segm(inf.baseaddr,  bottom, top, "TEXT", "CODE");
  create_filename_cmt();
  ph.notify(ph.loader);   // tell the module that the file has FLEX format
}

//----------------------------------------------------------------------
void idaapi load_file(linput_t *li,ushort /*_neflags*/,const char *fileformatname)
{
  if ( strcmp(fileformatname, object_name) == 0 )
    load_obj_file(li);
  else
    load_flex_file(li);
}

//--------------------------------------------------------------------------
bool idaapi init_loader_options(linput_t*)
{
  set_processor_type("6809", SETPROC_ALL|SETPROC_FATAL);
  return true;
}

//--------------------------------------------------------------------------
loader_t LDSC =
{
  IDP_INTERFACE_VERSION,
  0,                            // loader flags
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
  accept_file,
//
//      load file into the database.
//
  load_file,
//
//      create output file from the database.
//      this function may be absent.
//
  NULL,
//      take care of a moved segment (fix up relocations, for example)
  NULL,
//      initialize user configurable options based on the input file.
  init_loader_options,
};
