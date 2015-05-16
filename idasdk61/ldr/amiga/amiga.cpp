/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2000 by Ilfak Guilfanov, <ig@datarescue.com>
 *      ALL RIGHTS RESERVED.
 *
 */

//
//      AMIGA hunk file loader
//

#include "../idaldr.h"
#include "amiga.hpp"

#define SkipLong(Longs)   qlseek(li, 4 * (Longs), SEEK_CUR)
#define SkipWord(Words)   qlseek(li, 2 * (Words), SEEK_CUR)
#define SkipByte(Bytes)   qlseek(li, 1 * (Bytes), SEEK_CUR)

//------------------------------------------------------------------------------
static void help(void)
{
  ask_for_feedback("This file contains some untested records");
}

//------------------------------------------------------------------------------
static char *read_name(linput_t *li, char *buf, size_t bufsize, int Longs)
{
  if ( ssize_t(bufsize) > 0 )
  {
    size_t sz = Longs;
    if ( sz != 0 )
    {
      sz *= 4;
      if ( sz >= bufsize )
        sz = bufsize-1;
      lread(li, buf, sz);
    }
    buf[sz] = '\0';
  }
  return buf;
}

//------------------------------------------------------------------------------
void idaapi load_file(linput_t *li,ushort /*_neflags*/,const char * /*fileformatname*/)
{
  if ( ph.id != PLFM_68K ) set_processor_type("68040", SETPROC_ALL|SETPROC_FATAL);

  uint32 Type, Data, i;
  int nums;
  char NameString[MAXSTR];
  bool has_header = false;
  bool shortreloc = false;
  inf.baseaddr = 0;
  ea_t start = toEA(inf.baseaddr, 0);
  ea_t end = start;
  ea_t codestart = BADADDR;

//
//      The first pass
//
  qlseek(li, 0);
  while( true )
  {
    if ( (i = (uint32)qlread(li, &Type, 4)) != 4 )
    {
      if ( i )
        warning("There %s %d extra byte%s at end of file.", i == 1 ? "is" : "are", i, i == 1 ? "" : "s");
      break;
    }
    Type = swap32(Type);

    if ( Type == HUNK_DREL32 && has_header )
      Type = HUNK_DREL32EXE;

    switch ( Type & 0xFFFF )
    {
    case HUNK_UNIT:
      read_name(li, NameString, sizeof(NameString), mf_readlong(li));
      break;
    case HUNK_NAME:
      read_name(li, NameString, sizeof(NameString), mf_readlong(li));
      break;
    case HUNK_LIB:
      SkipLong(1);
      break;
    case HUNK_INDEX:
      {
        Data = mf_readlong(li);
        SkipByte((Data*4));
      }
      break;
    case HUNK_CODE:
    case HUNK_PPC_CODE:
    case HUNK_DATA:
    case HUNK_BSS:
      {
        Data = mf_readlong(li);
//        i = Data;
        Data <<= 2;
        Data &= 0x7FFFFFFF;
        start = freechunk(end, Data, -0xF);
        end = start + Data;
        const char *sname = NULL;
        sel_t sel = segs.get_area_qty() + 1;
        set_selector(sel, 0);
        switch ( Type&0xFFFF )
        {
          case HUNK_PPC_CODE:
            if ( ph.id != PLFM_PPC )
              set_processor_type("ppc", SETPROC_ALL|SETPROC_FATAL);
            sname = "PPC_CODE";
            break;
          case HUNK_CODE:
            sname = "CODE";
            if ( inf.start_cs == BADSEL )
            {
              inf.start_cs = sel;
              inf.startIP = start;
            }
            break;
          case HUNK_DATA:
            sname = "DATA";
            break;
          case HUNK_BSS:
            sname = "BSS";
            break;
        }
        if ( (Type & 0xFFFF) != HUNK_BSS )
          file2base(li, qltell(li), start, end, FILEREG_PATCHABLE);
        add_segm(sel, start, end, sname, sname);
//      printf("\t%6ld (%08lX) bytes", Data, Data);
//      if ( Type & HUNKF_CHIP)         printf(" _CHIP" );
//      if ( Type & HUNKF_FAST)         printf(" _FAST" );
//      if ( Type & HUNKF_ADVISORY)     printf(" _ADVISORY" );
//      if ( i & HUNKF_CHIP)            printf(" CHIP" );
//      if ( i & HUNKF_FAST)            printf(" FAST" );
//      if ( i & HUNKF_ADVISORY)                printf(" ADVISORY" );
      }
      break;
    case HUNK_RELOC32SHORT: case HUNK_DREL32EXE:
      shortreloc = true;
    case HUNK_RELRELOC32: case HUNK_ABSRELOC16: case HUNK_RELRELOC26:
    case HUNK_RELOC32: case HUNK_RELOC16: case HUNK_RELOC8:
    case HUNK_DREL32: case HUNK_DREL16: case HUNK_DREL8:
      nums = 0;
      while ( (Data=(shortreloc ? mf_readshort(li) : mf_readlong(li))) != 0 )
      {
        shortreloc ? mf_readshort(li) : mf_readlong(li);
        shortreloc ? SkipWord(Data) : SkipLong(Data);
        nums += Data;
      }
      if ( !(nums & 1) && shortreloc ) SkipWord(1 );
      shortreloc = false;
      break;
    case HUNK_EXT:
      while ( (Data=mf_readlong(li)) != 0 )
      {
        /* Is it followed by a symbol name? */
        if ( Data & 0xFFFFFF )
          read_name(li, NameString, sizeof(NameString), Data & 0xFFFFFF);

        /* Remember extension type. */
        int32 exttype = (Data >> 24) & 0xFF;

        /* Display value of symbol. */
        if ( exttype == EXT_DEF || exttype == EXT_ABS || exttype == EXT_RES )
          mf_readlong(li);

        /* Skip relocation information. */
        if ( exttype == EXT_REF32
          || exttype == EXT_REF16
          || exttype == EXT_REF8
//          || exttype == EXT_DEXT32
//          || exttype == EXT_DEXT16
//          || exttype == EXT_DEXT8
//          || exttype == EXT_RELREF32
          || exttype == EXT_RELREF26 )
        {
          SkipLong(mf_readlong(li));
        }

        /* Display size of common block. */
        if ( exttype == EXT_COMMON
//          || exttype == EXT_RELCOMMON
           )
        {
          mf_readlong(li);
          SkipLong(mf_readlong(li));
        }
      }
      break;
    case HUNK_SYMBOL:
      while ( (Data=mf_readlong(li)) != 0 )
      {
        read_name(li, NameString, sizeof(NameString), Data & 0xFFFFFF);
        mf_readlong(li);
      }
      break;
    case HUNK_DEBUG:
      SkipLong(mf_readlong(li));
      break;
    case HUNK_END:
      break;
    case HUNK_HEADER:
      {
        has_header = true;
        while ( (Data=mf_readlong(li)) != 0 )
          read_name(li, NameString, sizeof(NameString), Data);
        mf_readlong(li);
        int32 From = mf_readlong(li);
        int32 To = mf_readlong(li);
        SkipLong(To-From+1);
      }
      break;
    case HUNK_OVERLAY:
      {
        int32 TabSize = mf_readlong(li);
        if ( TabSize )
        {
          mf_readlong(li);
          SkipLong(TabSize);
        }
        int32 hunktype = mf_readlong(li);
        if ( TabSize && hunktype >= HUNK_UNIT && hunktype <= HUNK_ABSRELOC16 )
          qlseek(li, -4, SEEK_CUR);
      }
      break;
    case HUNK_BREAK:
      break;
    default:
      warning("Unknown hunk type %04X - Aborting!", Type & 0xFFFF);
      return;
    }
  }

//
//      The second pass
//
  qlseek(li, 0);
  int nseg = 0;
  while( true )
  {
    if ( (i = (uint32)qlread(li, &Type, 4)) != 4 )
    {
      break;
    }
    Type = swap32(Type);

    if ( Type == HUNK_DREL32 && has_header )
      Type = HUNK_DREL32EXE;

    switch ( Type & 0xFFFF )
    {
    case HUNK_UNIT:
      read_name(li, NameString, sizeof(NameString), mf_readlong(li));
      add_pgm_cmt("Unit: %s", NameString);
      break;
    case HUNK_NAME:
      read_name(li, NameString, sizeof(NameString), mf_readlong(li));
      add_pgm_cmt("Title: %s", NameString);
      break;
    case HUNK_LIB:
      mf_readlong(li);
      break;
    case HUNK_INDEX:
      {
        Data = mf_readlong(li);
        SkipByte((Data*4));
      }
      break;
    case HUNK_CODE:
    case HUNK_PPC_CODE:
    case HUNK_DATA:
    case HUNK_BSS:
      {
        Data = mf_readlong(li);
        Data <<= 2;
        Data &= 0x7FFFFFFF;
        if ( (Type & 0xFFFF) != HUNK_BSS )
          SkipByte(Data);
        nseg++;
      }
      break;
    case HUNK_RELOC32SHORT: case HUNK_DREL32EXE:
      shortreloc = true;
    case HUNK_RELRELOC32: case HUNK_ABSRELOC16: case HUNK_RELRELOC26:
    case HUNK_RELOC32: case HUNK_RELOC16: case HUNK_RELOC8:
    case HUNK_DREL32: case HUNK_DREL16: case HUNK_DREL8:
      nums = 0;
      while ( (Data=(shortreloc ? mf_readshort(li) : mf_readlong(li))) != 0 )
      {
        uint32 dat2 = shortreloc ? mf_readshort(li) : mf_readlong(li);
        segment_t *s = get_segm_by_sel(dat2+1);
        segment_t *ssrc = get_segm_by_sel(nseg);
        ea_t base = BADADDR;
        if ( ssrc != NULL )
          base = ssrc->startEA;
        else
          s = NULL;
        for(uint32 dat3 = Data; dat3; --dat3)
        {
          uint32 off = shortreloc ? mf_readshort(li) : mf_readlong(li);
          if ( s != NULL )
          {
            ea_t src = base + off;
            ea_t dst = s->startEA;
            fixup_data_t fd;
            ea_t target = BADADDR;
            switch ( Type & 0xFFFF )
            {
              case HUNK_RELRELOC32:
              case HUNK_RELOC32:
              case HUNK_DREL32:
              case HUNK_RELOC32SHORT:
              case HUNK_DREL32EXE:
                target = get_long(src)+dst;
                put_long(src, target);
                fd.type = FIXUP_OFF32;
                break;
              case HUNK_ABSRELOC16:
              case HUNK_RELRELOC26:
              case HUNK_RELOC16:
              case HUNK_DREL16:
                target = get_word(src)+dst;
                put_word(src, target);
                fd.type = FIXUP_OFF16;
                break;
              case HUNK_RELOC8:
              case HUNK_DREL8:
                target = get_byte(src)+dst;
                put_byte(src, (uint32)target);
                fd.type = FIXUP_OFF8;
                break;
            }
            fd.sel = ushort(dat2+1);
            fd.off = target;
            fd.displacement = 0;
            set_fixup(src, &fd);
          }
          else
            help();
        }
        nums += Data;
      }
      if ( !(nums & 1) && shortreloc ) SkipWord(1 );
      shortreloc = false;
      break;
    case HUNK_EXT:
      help();
      while ( (Data=mf_readlong(li)) != 0 )
      {
        switch ( (Data >> 24) & 0xFF )
        {
          case EXT_DEF:       msg("  EXT_DEF"); break;
          case EXT_ABS:       msg("  EXT_ABS"); break;
          case EXT_RES:       msg("  EXT_RES"); break;
          case EXT_REF32:     msg("  EXT_REF32"); break;
          case EXT_COMMON:    msg("  EXT_COMMON"); break;
          case EXT_REF16:     msg("  EXT_REF16"); break;
          case EXT_REF8:      msg("  EXT_REF8"); break;
//        case EXT_DEXT32:    msg("  EXT_DEXT32"); break;
//        case EXT_DEXT16:    msg("  EXT_DEXT16"); break;
//        case EXT_DEXT8:     msg("  EXT_DEXT8"); break;
//        case EXT_RELREF32:  msg("  EXT_RELREF32"); break;
//        case EXT_RELREF26:  msg("  EXT_RELREF26"); break;
//        case EXT_RELCOMMON: msg("  EXT_RELCOMMON"); break;
          default: msg("  EXT_??? (%02x)\n",(Data >> 24) & 0xFF); break;
        }

        /* Is it followed by a symbol name? */

        if ( Data & 0xFFFFFF )
        {
          read_name(li, NameString, sizeof(NameString), Data & 0xFFFFFF);
          msg(" %s", NameString);
        }

        /* Remember extension type. */
        int32 exttype = (Data >> 24) & 0xFF;

        /* Display value of symbol. */
        if ( exttype == EXT_DEF || exttype == EXT_ABS || exttype == EXT_RES )
        {
          if ( !(Data & 0xFFFFFF) )
            msg(" ???");

          Data = mf_readlong(li);
          msg("%08X", Data);
        }

        /* Skip relocation information. */
        if ( exttype == EXT_REF32
          || exttype == EXT_REF16
          || exttype == EXT_REF8
//          || exttype == EXT_DEXT32
//          || exttype == EXT_DEXT16
//          || exttype == EXT_DEXT8
//          || exttype == EXT_RELREF32
          || exttype == EXT_RELREF26 )
        {
          Data = mf_readlong(li);
          msg("= %d entr%s", Data, Data == 1 ? "y" : "ies");
          SkipLong(Data);
        }

        /* Display size of common block. */
        if ( exttype == EXT_COMMON
//          || exttype == EXT_RELCOMMON
           )
        {
          Data = mf_readlong(li);

          msg(" Size = %d bytes", Data << 2);
          Data = mf_readlong(li);
          SkipLong(Data);
        }
        msg("\n");
      }
      break;
    case HUNK_SYMBOL:
      while ( (Data=mf_readlong(li)) != 0 )
      {
        /* Display name. */
        read_name(li, NameString, sizeof(NameString), Data & 0xFFFFFF);

        /* Display value. */
        Data = mf_readlong(li);

        segment_t *ssrc = get_segm_by_sel(nseg);
        if ( ssrc == NULL )
          help();
        else
          set_name(ssrc->startEA+Data, NameString, SN_NOWARN);
      }
      break;
    case HUNK_DEBUG:
      SkipLong(mf_readlong(li));
      break;
    case HUNK_END:
      break;
    case HUNK_HEADER:
      {
        has_header = true;
        while ( (Data=mf_readlong(li)) != 0 )
          read_name(li, NameString, sizeof(NameString), Data);
        mf_readlong(li);
        int32 From = mf_readlong(li);
        int32 To = mf_readlong(li);
        SkipLong(To-From+1);
      }
      break;
    case HUNK_OVERLAY:
      {
        int32 TabSize = mf_readlong(li);
        if ( TabSize )
        {
          mf_readlong(li);
          SkipLong(TabSize);
        }
        int32 hunktype = mf_readlong(li);
        if ( TabSize && hunktype >= HUNK_UNIT && hunktype <= HUNK_ABSRELOC16 )
          qlseek(li, -4, SEEK_CUR);
      }
      break;
    case HUNK_BREAK:
      break;
    default:
      warning("Unknown hunk type %04X - Aborting!", Type & 0xFFFF);
      return;
    }
  }

  create_filename_cmt();
  if ( codestart != BADADDR )
  {
    inf.start_cs = 0;
    inf.startIP = codestart;
  }
}

//--------------------------------------------------------------------------
int idaapi accept_file(linput_t *li,char fileformatname[MAX_FILE_FORMAT_NAME],int n)
{
  if ( n != 0 ) return 0;
  qlseek(li, 0);
  uint32 type;
  if ( qlread(li, &type, sizeof(uint32)) == sizeof(uint32) && swap32(type) == HUNK_HEADER )
  {
    qstrncpy(fileformatname, "Amiga hunk file", MAX_FILE_FORMAT_NAME);
    return true;
  }
  return 0;
}

//--------------------------------------------------------------------------
bool idaapi init_loader_options(linput_t*)
{
  set_processor_type("68040", SETPROC_ALL|SETPROC_FATAL);
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
