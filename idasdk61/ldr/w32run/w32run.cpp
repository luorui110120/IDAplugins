/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      Watcom DosExtender loader.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

/*
        L O A D E R  for Watcom W32RUN DOS32-extender
*/

#include "../idaldr.h"
#include <exehdr.h>
#include <queue.hpp>
#include "w32run.h"
#include <stddef.h>   //offsetof

//--------------------------------------------------------------------------
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
int idaapi accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
  union  {
    exehdr  ex;
    w32_hdr wh;
  };
  uint32 pos, fl;

  if ( n) return(0 );

  if ( qlread(li, &ex, sizeof(ex)) != sizeof(ex ) ||
     ex.exe_ident != EXE_ID || (pos = ex.HdrSize) == 0) return(0);
  fl = qlsize(li);
  qlseek(li, pos *= 16, SEEK_SET);
  if ( qlread(li, &wh, sizeof(wh)) != sizeof(wh)) return(0 );
  if ( wh.ident != W32_ID || wh.beg_fileoff < pos+sizeof(wh ) ||
//   ph->memsize >= MAXLOADMEM ||
     wh.read_size > wh.mem_size ||
     wh.start_offset >= wh.reltbl_offset ||
     wh.beg_fileoff > fl || wh.read_size > fl - wh.beg_fileoff ||
     wh.reltbl_offset > wh.read_size - 2) return(0);

  qstrncpy(fileformatname, "Watcom DOS32-extender file", MAX_FILE_FORMAT_NAME);
  return(f_W32RUN);
}

//--------------------------------------------------------------------------

static w32_hdr wh;
static uint32 minea, topea;
static linput_t *li;

//-------------------------------------------------------------------------
static int mread(void *buf, size_t size)
{
  if ( size_t(qlread(li, buf, size)) == size) return(0 );
  if ( askyn_c(0, "HIDECANCEL\nRead error or bad file structure. Continue loading?") <= 0 )
    loader_failure();
  return(1);
}

//-------------------------------------------------------------------------
static void realize_relocation(void)
{
  fixup_data_t fd;
  char first = 0;
  ushort cnt, tmp;
  register uint32 offset;
  uint32 curv, maxv = 0, ost = wh.read_size - wh.reltbl_offset;

  fd.type = FIXUP_OFF32;
  fd.displacement = 0;

  msg("Reading relocation table...\n");

  for( ; ; ) {
    if ( ost < sizeof(short) ) { first = -1; break; }
    ost -= sizeof(short);
    if ( mread(&cnt, sizeof(cnt)) ) return;
    if ( !cnt ) break;
    if ( ost < sizeof(int32) ) { first = -1; break; }
    ost -= sizeof(int32);
    if ( mread(&tmp, sizeof(tmp)) ) return;
    offset = (uint32)tmp << 16;
    if ( mread(&tmp, sizeof(tmp)) ) return;
    offset |= tmp;
    for( ; ; ) {
      if ( offset > wh.reltbl_offset - 4 ) {
        if ( !first ) {
          ++first;
          warning("Bad value(s) in relocation table!");
        }
      } else {
        uint32 ea = minea + offset;
        showAddr(ea);
        if ( (curv = get_long(ea)) >= wh.mem_size ) {
          msg("Doubtful value after relocation! (%x=>%x)\n", ea,
                                                            curv + minea);
          QueueMark(Q_att, ea);
        } else if ( curv > maxv ) maxv = curv;
        curv += minea;
        put_long(ea, curv);
        fd.off = offset;
        fd.sel = curv >= topea ? 2 : 1;
        set_fixup(ea, &fd);
      }
      if ( --cnt == 0 ) break;
      if ( ost < sizeof(short) ) { first = -1; break; }
      ost -= sizeof(short);
      if ( mread(&tmp, sizeof(tmp)) ) return;
      offset += tmp;
    }
  }
  if ( first < 0) warning("Truncated relocation table!" );
  if ( !first && ost) warning("Information after relocation table!" );
  if(!ost && !first && maxv > wh.start_offset &&
     (maxv += minea) < topea)       set_segm_end(topea, maxv, SEGMOD_KILL);
}

//--------------------------------------------------------------------------
static void add_all_comments(void)
{
  create_filename_cmt();
  add_pgm_cmt("Full size of allocation memmory: %0Xh", wh.mem_size);
  add_pgm_cmt("Calling convention for W32RUN\n\n"
              "  ah     - OS type\n"
              "  ecx    - low stack limit\n"
              "  bx:edx - int 21h interface\n"
              "  edi    - struct {");
  add_pgm_cmt("                    char * ModuleFileName;\n"
              "                    char * CommandLine;\n"
              "                    char * Environment;");
  add_pgm_cmt("                    char * ExeTrademarkString;\n"
              "                    long   SystemDepenced_1;\n"
              "                    long   SystemDepenced_2;");
  add_pgm_cmt("                   }");

  set_cmt(inf.startIP, "Calling convention declared in file header", 1);
}

//--------------------------------------------------------------------------
//
//      load file into the database.
//
void idaapi load_file(linput_t *_li, ushort /*neflag*/, const char * /*fileformatname*/)
{
  ushort pos;

  if ( ph.id != PLFM_386 )
    set_processor_type("80386r", SETPROC_ALL|SETPROC_FATAL);

  qlseek(li = _li, offsetof(exehdr, HdrSize));
  lread(li, &pos, sizeof(pos));
  qlseek(li, (uint32)pos * 16);
  lread(li, &wh, sizeof(wh));

  inf.baseaddr = 0;
//  inf.s_prefflag &= ~PREF_SEGADR;
//  inf.nametype = NM_EA4;
  inf.lflags |= LFLG_PC_FLAT;
  minea = (uint32)toEA(W32_DOS_LOAD_BASE, 0);
  inf.startIP = minea + wh.start_offset;
  inf.start_cs = 1; //selector of code
  topea = minea + wh.reltbl_offset;
  file2base(li, wh.beg_fileoff, minea, topea, FILEREG_PATCHABLE);
  set_selector(1, 0);
  if ( !add_segm(1, minea, topea, NAME_CODE, CLASS_CODE)) loader_failure( );
  set_segm_addressing(getseg(minea), 1);
  set_selector(2, 0);
  if ( !add_segm(2, topea, minea+wh.mem_size, NAME_BSS, CLASS_BSS)) loader_failure( );
  set_segm_addressing(getseg(topea), 1);
  set_default_dataseg(1);
  realize_relocation();
  add_all_comments();
}

//----------------------------------------------------------------------
bool idaapi init_loader_options(linput_t*)
{
  set_processor_type("80386r", SETPROC_ALL|SETPROC_FATAL);
  return true;
}

//----------------------------------------------------------------------
//
//      LOADER DESCRIPTION BLOCK
//
//----------------------------------------------------------------------
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
