/*
 *      Interactive disassembler (IDA).
 *      Version 4.20
 *      Copyright (c) 2002 by Ilfak Guilfanov. (ig@datarescue.com)
 *      ALL RIGHTS RESERVED.
 *
 */

//
//      Intel OMF386
//

#include "../idaldr.h"
#include "intelomf.hpp"
#include "common.cpp"

static lmh h;
static ea_t xea;
static sel_t dsel = BADSEL;
//-----------------------------------------------------------------------
static void show_segdefs(linput_t *li, uint32 offset, uint32 length)
{
  if ( offset == 0 || length == 0 ) return;
  qlseek(li, offset);
  int n = 0;
  for ( int i=0; i < length; )
  {
    segdef s;
    const int size = offsetof(segdef, combine_name);
    lread(li, &s, size);
    int nlen = read_pstring(li, s.combine_name, sizeof(s.combine_name));
    i += size + 1 + nlen;
    n++;

    const char *sname = s.combine_name;
    const char *sclas = sname;
    if ( strnicmp(sname, "CODE", 4) == 0 ) sclas = "CODE";
    if ( strnicmp(sname, "DATA", 4) == 0 ) sclas = "DATA";
    if ( strnicmp(sname, "CONST", 5) == 0 ) sclas = "CONST";
    if ( stricmp(sname, "STACK") == 0 ) sclas = "STACK";
    if ( strchr(sname, ':') != NULL ) continue;

    int segsize = s.slimit + 1;
    if ( strcmp(sname, "DATA") == 0 ) dsel = n;
    set_selector(n, 0);
    ea_t ea = freechunk(inf.maxEA, segsize, -(1<<s.align));
    add_segm(n, ea, ea+segsize, sname, sclas);
    set_segm_addressing(getseg(ea), true);
    if ( strcmp(sclas, "STACK") == 0 )
      doByte(ea, segsize);
  }
}

//-----------------------------------------------------------------------
static ea_t getsea(ushort i)
{
  segment_t *s = get_segm_by_sel(i & 0xFF);
  return s ? s->startEA : BADADDR;
}

//-----------------------------------------------------------------------
static void show_pubdefs(linput_t *li, uint32 offset, uint32 length)
{
  if ( offset == 0 || length == 0 ) return;
  qlseek(li, offset);
  for ( int i=0; i < length; )
  {
    pubdef p;
    const int size = offsetof(pubdef, sym_name);
    lread(li, &p, size);
    int nlen = read_pstring(li, p.sym_name, sizeof(p.sym_name));
    i += size + 1 + nlen;

    ea_t sea = getsea(p.PUB_segment);
    if ( sea != BADADDR )
    {
      sea += p.PUB_offset;
      add_entry(sea, sea, p.sym_name, segtype(sea) == SEG_CODE);
    }
  }
}

//-----------------------------------------------------------------------
static void show_extdefs(linput_t *li, uint32 offset, uint32 length)
{
  if ( offset == 0 || length == 0 ) return;
  qlseek(li, offset);

  inf.specsegs = 1;
  int segsize = 4 * h.num_externals;
  if ( segsize < 0 || segsize < h.num_externals )
    loader_failure("bad extdefs");
  sel_t sel = h.num_segs+1;
  set_selector(sel, 0);
  xea = freechunk(inf.maxEA, segsize, -15);
  add_segm(sel, xea, xea+segsize, "XTRN", "XTRN");
  set_segm_addressing(getseg(xea), true);

  int n = 0;
  for ( int i=0; i < length; n++ )
  {
    extdef p;
    const int size = offsetof(extdef, allocate_len);
    lread(li, &p, size);
    p.allocate_len.len_4 = 0;
    if ( p.allocate )
    {
      ask_for_feedback("extdef.allocate\n");
      lread(li, &p.allocate_len.len_4, sizeof(p.allocate_len.len_4));
    }
    int nlen = read_pstring(li, p.sym_name, sizeof(p.sym_name));
    i += size + 1 + nlen;

    ea_t a = xea + 4*n;
    set_name(a, p.sym_name);
    if ( p.allocate )
      put_long(a, p.allocate_len.len_4);
  }
}

//-----------------------------------------------------------------------
static void read_text(linput_t *li)
{
  text txt;
  const int size = offsetof(text, segment);
  lread(li, &txt, size);
  if ( txt.length != 0 )
  {
    uint32 fptr = qltell(li);
    ea_t sea = getsea(txt.txt_IN);
    if ( sea != BADADDR )
    {
      sea += txt.txt_offset;
      file2base(li, fptr, sea, sea+txt.length, FILEREG_PATCHABLE);
    }
    qlseek(li, fptr+txt.length);
  }
}

//-----------------------------------------------------------------------
static void read_fixup(linput_t *li)
{
  fixup fix;
  const int size = offsetof(fixup, fixups);
  lread(li, &fix, size);
  uint32 fptr = qltell(li);
  ea_t sea = getsea(fix.where_IN);
  if ( sea != BADADDR )
  {
    uchar *b = qalloc_array<uchar>(fix.length);
    if ( b == NULL ) nomem("read_fixup");
    lread(li, b, fix.length);

//    show_hex(b, fix.length, "\nFIXUP SEG %04X, %04X BYTES, KIND %02X\n",
//                  fix.where_IN,
//                  fix.length,
//                  b[0]);

    const uchar *ptr = b;
    const uchar *end = b + fix.length;
    while ( ptr < end )
    {
      fixup_data_t fd;
      uint32 where_offset = 0;
      uint32 what_offset = 0;
      ushort what_in = 9;
      bool selfrel = false;
      bool isfar = false;
      fd.type = FIXUP_OFF32;
      switch ( *ptr++ )
      {
        case 0x2C:      // GEN
          isfar = true;
          ask_for_feedback("Untested relocation type");
        case 0x24:      // GEN
          where_offset = readdw(ptr, false);
          what_offset = readdw(ptr, false);
          what_in = (ushort)readdw(ptr, false);
          break;
        case 0x2D:
          isfar = true;
        case 0x25:      // INTRA
          where_offset = readdw(ptr, false);
          what_offset = readdw(ptr, false);
          what_in = fix.where_IN;
          break;
        case 0x2A:      // CALL
          where_offset = readdw(ptr, false);
          what_offset = 0;
          what_in = (ushort)readdw(ptr, false);
          selfrel = true;
          break;
        case 0x2E:      // OFF32?
          isfar = true;
        case 0x26:
          where_offset = readdw(ptr, false);
          what_offset = 0;
          what_in = (ushort)readdw(ptr, false);
          break;
        default:
          ask_for_feedback("Unknown relocation type %02X", ptr[-1]);
          add_pgm_cmt("!!! Unknown relocation type %02X", ptr[-1]);
          break;
      }
      ea_t source = sea + where_offset;
      ea_t target = BADADDR;
      switch ( what_in >> 12 )
      {
        case 0x02:      // segments
          target = getsea(what_in);
          break;
        case 0x06:      // externs
          target = xea + 4 * ((what_in & 0xFFF) - 1);
          fd.type |= FIXUP_EXTDEF;
          break;
        default:
          ask_for_feedback("Unknown relocation target %04X", what_in);
          add_pgm_cmt("!!! Unknown relocation target %04X", what_in);
          break;
      }
      segment_t *ts = getseg(target);
      fd.sel = ts ? (ushort)ts->sel : 0;
      if ( (fd.type & FIXUP_EXTDEF) == 0 )
      {
        target += what_offset;
        what_offset = 0;
      }
      fd.off = target;
      fd.displacement = what_offset;
      target += what_offset;
      if ( selfrel )
      {
        fd.type |= FIXUP_SELFREL;
        target -= source + 4;
      }
      set_fixup(source, &fd);
      put_long(source, target);
      if ( isfar )
      {
        fd.type = FIXUP_SEG16;
        set_fixup(source+4, &fd);
        put_word(source+4, fd.sel);
      }
    }
    qfree(b);
  }
  qlseek(li, fptr + fix.length);
}

//-----------------------------------------------------------------------
static void read_iterat(linput_t *li)
{
  iterat itr;
  const int size = offsetof(iterat, text) + offsetof(temp, value);
  lread(li, &itr, size);
  itr.text.value = NULL;
  if ( itr.text.length != 0 )
  {
    uint32 fptr = qltell(li);
    ea_t sea = getsea(itr.it_segment);
    if ( sea != BADADDR )
    {
      sea += itr.it_offset;
      for ( int i=0; i < itr.it_count; i++ )
      {
        ea_t eea = sea + itr.text.length;
        file2base(li, fptr, sea, eea, FILEREG_PATCHABLE);
        sea = eea;
      }
    }
    qlseek(li, fptr+itr.text.length);
  }
}

//-----------------------------------------------------------------------
static void show_txtfixs(linput_t *li, uint32 offset, uint32 length)
{
  if ( offset == 0 || length == 0 ) return;
  qlseek(li, offset);
  uint32 eoff = offset + length;
  while ( qltell(li) < eoff )
  {
    char type;
    lread(li, &type, sizeof(type));
    switch ( type )
    {
      case 0:
        read_text(li);
        break;
      case 1:
        read_fixup(li);
        break;
      case 2:
        read_iterat(li);
        break;
      default:
        ask_for_feedback("txtfix.blk_type == %d!\n", type);
        return;
    }
  }
}

//--------------------------------------------------------------------------
int idaapi accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
  if ( n == 0 && is_intelomf_file(li) )
  {
    qstrncpy(fileformatname, "Intel OMF386", MAX_FILE_FORMAT_NAME);
    return 1;
  }
  return 0;
}

//--------------------------------------------------------------------------
void idaapi load_file(linput_t *li, ushort /*neflag*/, const char * /*fileformatname*/)
{
  qlseek(li, 1);
  lread(li, &h, sizeof(h));

  toc_p1 toc;
  lread(li, &toc, sizeof(toc));

  // we add one to skip the magic byte
  show_segdefs(li, toc.SEGDEF_loc+1, toc.SEGDEF_len);
  show_pubdefs(li, toc.PUBDEF_loc+1, toc.PUBDEF_len);
  show_extdefs(li, toc.EXTDEF_loc+1, toc.EXTDEF_len);
  show_txtfixs(li, toc.TXTFIX_loc+1, toc.TXTFIX_len);

  if ( dsel != BADSEL ) set_default_dataseg(dsel);
  add_pgm_cmt("Module: %*.*s", h.mod_name[0], uchar(h.mod_name[0]), &h.mod_name[1]);
}

//--------------------------------------------------------------------------
loader_t LDSC =
{
  IDP_INTERFACE_VERSION,
  0,                   // loader flags
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
};
