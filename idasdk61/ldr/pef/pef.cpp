/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *                              FIDO:   2:5020/209
 *
 *      PEF Loader
 *      ----------
 *
 */

#include "../idaldr.h"
#include "pef.hpp"
#include "../coff/syms.h"
#include "common.cpp"

static ea_t toc_ea;
static netnode toc;
//----------------------------------------------------------------------
static const char *get_sec_share_name(uint8 share, char *buf, size_t bufsize)
{
  switch ( share )
  {
    case PEF_SH_PROCESS: return "Shared within process";
    case PEF_SH_GLOBAL : return "Shared between all processes";
    case PEF_SH_PROTECT: return "Shared between all processes but protected";
    default:
      qsnprintf(buf, bufsize, "Unknown code %d", share);
      return buf;
  }
}

//----------------------------------------------------------------------
static void process_vector(uint32 ea, const char *name)
{
  set_offset(ea, 0, 0);
  set_offset(ea+4, 0, 0);
  uint32 mintoc = get_long(ea+4);
  if ( segtype(mintoc) == SEG_DATA && mintoc < toc_ea )
  {
    toc_ea = mintoc;
    ph.notify(processor_t::idp_notify(ph.loader+1), toc_ea);
  }
  set_name(ea, name);
  char buf[MAXSTR];
  qsnprintf(buf, sizeof(buf), ".%s", name);
  uint32 code = get_long(ea);
  add_entry(code, code, buf, true);
  make_name_auto(code);
}

//----------------------------------------------------------------------
static void process_symbol_class(uint32 ea, uchar sclass, const char *name)
{
  switch ( sclass )
  {
    case kPEFCodeSymbol :
    case kPEFGlueSymbol :
      add_entry(ea, ea, name, true);
      break;
    case kPEFTVectSymbol:
      process_vector(ea, name);
      break;
    case kPEFTOCSymbol  :
      if ( segtype(ea) == SEG_DATA && ea < toc_ea )
      {
        toc_ea = ea;
        ph.notify(processor_t::idp_notify(ph.loader+1), toc_ea);
      }
      toc.charset(ea, XMC_TD+1, 1);
      /* fall thru */
    case kPEFDataSymbol :
      set_name(ea, name);
      break;
  }
}

//----------------------------------------------------------------------
static void fixup(uint32 ea, uint32 delta, int extdef)
{
  fixup_data_t fd;
  fd.type = FIXUP_OFF32;
  if ( extdef )
    fd.type |= FIXUP_EXTDEF;
  segment_t *s = getseg(delta);
  fd.displacement = get_long(ea);
  if ( s == NULL )
  {
    fd.sel = 0;
    fd.off = delta;
  }
  else
  {
    fd.sel = (ushort)s->sel;
    fd.off = delta - get_segm_base(s);
  }
  set_fixup(ea, &fd);
  uint32 target = get_long(ea) + delta;
  put_long(ea, target);
  set_offset(ea, 0, 0);
  cmd.ea = ea; ua_add_dref(0, target, dr_O); cmd.ea = BADADDR;
  if ( target != toc_ea
    && !has_name(get_flags_novalue(ea))
    && has_name(get_flags_novalue(target)) )
  {
    char buf[MAXSTR];
    if ( get_true_name(BADADDR, target, &buf[3], sizeof(buf)-3) != NULL )
    {
      buf[0] = 'T';
      buf[1] = 'C';
      buf[2] = '_';
      do_name_anyway(ea, buf);
      make_name_auto(ea);
    }
  }
//  toc.charset(ea,XMC_TC+1,1);
}

//----------------------------------------------------------------------
static NORETURN void bad_loader_data(void)
{
  loader_failure("Bad loader data");
}

//----------------------------------------------------------------------
static NORETURN void bad_reloc_data(void)
{
  loader_failure("Bad relocation info");
}

//----------------------------------------------------------------------
static bool inside(const bytevec_t &vec, const void *ptr)
{
  const uchar *p = (const uchar *)ptr;
  return vec.begin() <= p && p < vec.end();
}

//----------------------------------------------------------------------
static bool inside_or_end(const bytevec_t &vec, const void *end)
{
  const uchar *p = (const uchar *)end;
  return vec.begin() <= p && p <= vec.end();
}

//----------------------------------------------------------------------
static void process_loader_data(bytevec_t &ldrdata, const qvector<pef_section_t> &sec)
{
  if ( ldrdata.size() < sizeof(pef_loader_t) )
    bad_loader_data();
  pef_loader_t &pl = *(pef_loader_t *)ldrdata.begin();
  swap_pef_loader(pl);
  pef_library_t *pil = (pef_library_t *)(&pl + 1);
  uint32 *impsym = (uint32 *)(pil + pl.importLibraryCount);
  pef_reloc_header_t *prh =
                (pef_reloc_header_t *)(impsym + pl.totalImportedSymbolCount);
  char *stable = (char *)(ldrdata.begin() + pl.loaderStringsOffset);
  uint16 *relptr = (uint16 *)(ldrdata.begin() + pl.relocInstrOffset);
  uint32 *hash = (uint32 *)(ldrdata.begin() + pl.exportHashOffset);
  uint32 hashsize = (1 << pl.exportHashTablePower);
  uint32 *keytable = hash + hashsize;
  pef_export_t *pe = (pef_export_t *)(keytable + pl.exportedSymbolCount);

  if ( !inside_or_end(ldrdata, impsym)
//    || !inside_or_end(ldrdata, impsym+pl.totalImportedSymbolCount)
    || !inside_or_end(ldrdata, prh)
    || !inside_or_end(ldrdata, prh+pl.relocSectionCount)
    || !inside_or_end(ldrdata, stable)
    || !inside_or_end(ldrdata, relptr)
    || !inside_or_end(ldrdata, keytable)
    || !inside_or_end(ldrdata, pe)
    || !inside_or_end(ldrdata, pe+pl.exportedSymbolCount)
    || pl.termSection != -1 && pl.termSection >= sec.size()
    || pl.initSection != -1 && pl.initSection >= sec.size()
    || pl.mainSection != -1 && pl.mainSection >= sec.size() )
  {
    bad_loader_data();
  }
#if !__MF__
  for ( int i=0; i < pl.importLibraryCount; i++ )
    swap_pef_library(pil[i]);
  for ( int i=0; i < pl.relocSectionCount; i++ )
    swap_pef_reloc_header(prh[i]);
  for ( int i=0; i < pl.exportedSymbolCount; i++ )
    swap_pef_export(pe[i]);
#endif

  if ( pl.totalImportedSymbolCount != 0 )
  {
    uint32 size = pl.totalImportedSymbolCount*4;
    ea_t undef = freechunk(inf.maxEA, size, -0xF);
    ea_t end = undef + size;
    set_selector(sec.size()+1, 0);
    if ( !add_segm(sec.size()+1, undef, end, "IMPORT", "XTRN"))
      loader_failure();

    for ( int i=0; i < pl.importLibraryCount; i++ )
    {
      ea_t ea = undef + 4 * pil[i].firstImportedSymbol;
      const char *libname = stable + pil[i].nameOffset;
      if ( !inside(ldrdata, libname) )
        bad_loader_data();
      add_long_cmt(ea, 1, "Imports from library %s", libname);
      if ( (pil[i].options & PEF_LIB_WEAK) != 0 )
        add_long_cmt(ea, 1, "Library is weak");
    }

    inf.specsegs = 1;
    for ( int i=0; i < pl.totalImportedSymbolCount; i++ )
    {
      uint32 sym = mflong(impsym[i]);
      uchar sclass = uchar(sym >> 24);
      ea_t ea = undef + 4*i;
      const char *iname = get_impsym_name(stable, ldrdata.end(), impsym, i);
      if ( iname == NULL )
        bad_loader_data();
      set_name(ea, iname);
      if ( (sclass & kPEFWeak) != 0 )
        make_name_weak(ea);
      doDwrd(ea,4);
      put_long(ea, 0);
      impsym[i] = (uint32)ea;
    }
  }

  if ( pl.mainSection != -1 )
  {
    uint32 ea = sec[pl.mainSection].defaultAddress + pl.mainOffset;
    toc_ea = sec[1].defaultAddress + get_long(ea+4);
    ph.notify(processor_t::idp_notify(ph.loader+1), toc_ea);
  }
  else if ( pl.initSection != -1 )
  {
    uint32 ea = sec[pl.initSection].defaultAddress + pl.initOffset;
    toc_ea = sec[1].defaultAddress + get_long(ea+4);
    ph.notify(processor_t::idp_notify(ph.loader+1), toc_ea);
  }

  if ( getenv("IDA_NORELOC") != NULL )
    goto EXPORTS;

  msg("Processing relocation information... ");
  for ( int i=0; i < pl.relocSectionCount; i++ )
  {
    int sidx = prh[i].sectionIndex;
    if ( sidx >= sec.size() )
      bad_reloc_data();
    uint32 sea = sec[sidx].defaultAddress;
    uint16 *ptr = relptr + prh[i].firstRelocOffset;
    if ( !inside(ldrdata, ptr) || !inside_or_end(ldrdata, ptr+prh[i].relocCount) )
      bad_reloc_data();
    uint32 reladdr = sea;
    uint32 import  = 0;
    uint32 code    = sec.size() > 0 ? sec[0].defaultAddress : 0;
    uint32 data    = sec.size() > 1 ? sec[1].defaultAddress : 0;
    int32 repeat   = -1;
    for ( int j=0; j < prh[i].relocCount; )
    {
      uint16 insn = mfshort(ptr[j++]);
      uint16 cnt = insn & 0x1FF;
      switch ( insn >> 9 )
      {
        default:  // kPEFRelocBySectDWithSkip= 0x00,/* binary: 00xxxxx */
          if ( (insn & 0xC000) == 0 )
          {
            int skipCount = (insn >> 6) & 0xFF;
            int relocCount = insn & 0x3F;
            reladdr += skipCount * 4;
            while ( relocCount > 0 )
            {
              relocCount--;
              fixup(reladdr, data, 0);
              reladdr += 4;
            }
            break;
          }
          bad_reloc_data();

        case kPEFRelocBySectC:  //     = 0x20,  /* binary: 0100000 */
          cnt++;
          while ( cnt > 0 )
          {
            cnt--;
            fixup(reladdr, code, 0);
            reladdr += 4;
          }
          break;
        case kPEFRelocBySectD:
          cnt++;
          while ( cnt > 0 )
          {
            cnt--;
            fixup(reladdr, data, 0);
            reladdr += 4;
          }
          break;
        case kPEFRelocTVector12:
          cnt++;
          while ( cnt > 0 )
          {
            cnt--;
            fixup(reladdr, code, 0);
            reladdr += 4;
            fixup(reladdr, data, 0);
            reladdr += 4;
            reladdr += 4;
          }
          break;
        case kPEFRelocTVector8:
          cnt++;
          while ( cnt > 0 )
          {
            cnt--;
            fixup(reladdr, code, 0);
            reladdr += 4;
            fixup(reladdr, data, 0);
            reladdr += 4;
          }
          break;
        case kPEFRelocVTable8:
          cnt++;
          while ( cnt > 0 )
          {
            cnt--;
            fixup(reladdr, data, 0);
            reladdr += 4;
            reladdr += 4;
          }
          break;
        case kPEFRelocImportRun:
          cnt++;
          if ( import+cnt > pl.totalImportedSymbolCount )
            bad_reloc_data();
          while ( cnt > 0 )
          {
            cnt--;
            fixup(reladdr, impsym[import], 1);
            import++;
            reladdr += 4;
          }
          break;
        case kPEFRelocSmByImport:
          if ( cnt >= pl.totalImportedSymbolCount )
            bad_reloc_data();
          fixup(reladdr, impsym[cnt], 1);
          reladdr += 4;
          import = cnt + 1;
          break;
        case kPEFRelocSmSetSectC:
          if ( cnt >= sec.size() )
            bad_reloc_data();
          code = sec[cnt].defaultAddress;
          break;
        case kPEFRelocSmSetSectD:
          if ( cnt >= sec.size() )
            bad_reloc_data();
          data = sec[cnt].defaultAddress;
          break;
        case kPEFRelocSmBySection:
          if ( cnt >= sec.size() )
            bad_reloc_data();
          fixup(reladdr, sec[cnt].defaultAddress, 0);
          reladdr += 4;
          break;

        case kPEFRelocIncrPosition: /* binary: 1000xxx */
        case kPEFRelocIncrPosition+1:
        case kPEFRelocIncrPosition+2:
        case kPEFRelocIncrPosition+3:
        case kPEFRelocIncrPosition+4:
        case kPEFRelocIncrPosition+5:
        case kPEFRelocIncrPosition+6:
        case kPEFRelocIncrPosition+7:
          reladdr += (insn & 0x0FFF)+1;
          break;

        case kPEFRelocSmRepeat:   /* binary: 1001xxx */
        case kPEFRelocSmRepeat+1:
        case kPEFRelocSmRepeat+2:
        case kPEFRelocSmRepeat+3:
        case kPEFRelocSmRepeat+4:
        case kPEFRelocSmRepeat+5:
        case kPEFRelocSmRepeat+6:
        case kPEFRelocSmRepeat+7:
          if ( repeat == -1 )
            repeat = (insn & 0xFF)+1;
          repeat--;
          if ( repeat != -1 )
            j -= ((insn>>8) & 15)+1 + 1;
          break;

        case kPEFRelocSetPosition:  /* binary: 101000x */
        case kPEFRelocSetPosition+1:
          {
            ushort next = mfshort(ptr[j++]);
            uint32 offset = next | (uint32(insn & 0x3FF) << 16);
            reladdr = sea + offset;
          }
          break;

        case kPEFRelocLgByImport: /* binary: 101001x */
        case kPEFRelocLgByImport+1:
          {
            ushort next = mfshort(ptr[j++]);
            uint32 index = next | (uint32(insn & 0x3FF) << 16);
            if ( index >= pl.totalImportedSymbolCount )
              bad_reloc_data();
            fixup(reladdr, impsym[index], 1);
            reladdr += 4;
            import = index + 1;
          }
          break;

        case kPEFRelocLgRepeat:   /* binary: 101100x */
        case kPEFRelocLgRepeat+1:
          {
            ushort next = mfshort(ptr[j++]);
            if ( repeat == -1 )
              repeat = next | (uint32(insn & 0x3F) << 16);
            repeat--;
            if ( repeat != -1 )
              j -= ((insn >> 6) & 15) + 1 + 2;
          }
          break;

        case kPEFRelocLgSetOrBySection: /* binary: 101101x */
        case kPEFRelocLgSetOrBySection+1:
          {
            ushort next = mfshort(ptr[j++]);
            uint32 index = next | (uint32(insn & 0x3F) << 16);
            if ( index >= sec.size() )
              bad_reloc_data();
            int subcode = (insn >> 6) & 15;
            switch ( subcode )
            {
              case 0:
                fixup(reladdr, sec[index].defaultAddress, 0);
                reladdr += 4;
                break;
              case 1:
                code = sec[index].defaultAddress;
                break;
              case 2:
                data = sec[index].defaultAddress;
                break;
            }
          }
          break;
      }
    }
  }

EXPORTS:
  for ( int i=0; i < pl.exportedSymbolCount; i++ )
  {
    uchar sclass = uchar(pe[i].classAndName >> 24);
    char name[MAXSTR];
    uint32 ea;
    switch ( pe[i].sectionIndex )
    {
      case -3:
        {
          uint symidx = pe[i].symbolValue;
          if ( symidx >= pl.totalImportedSymbolCount )
            bad_reloc_data();
          ea = impsym[symidx];
        }
        break;
      case -2:  // absolute symbol
        ask_for_feedback("Absolute symbols are not implemented");
        continue;
      default:
        {
          uint secidx = pe[i].sectionIndex;
          if ( secidx >= sec.size() )
            bad_reloc_data();
          ea = sec[secidx].defaultAddress + pe[i].symbolValue;
        }
        break;
    }
    if ( !get_expsym_name(stable, keytable, pe, i, ldrdata.end(), name, sizeof(name)) )
      bad_loader_data();
    process_symbol_class(ea, sclass & 0xF, name);
  }
  msg("done.\n");

  if ( pl.mainSection != -1 )
  {
    uint32 ea = sec[pl.mainSection].defaultAddress + pl.mainOffset;
    process_vector(ea, "start");
    inf.start_cs = 0;
    inf.startIP  = get_long(ea);
  }
  if ( pl.initSection != -1 )
  {
    uint32 ea = sec[pl.initSection].defaultAddress + pl.initOffset;
    process_vector(ea, "INIT_VECTOR");
  }
  if ( pl.termSection != -1 )
  {
    uint32 ea = sec[pl.termSection].defaultAddress + pl.termOffset;
    process_vector(ea, "TERM_VECTOR");
  }

  if ( toc_ea != BADADDR )
    set_name(toc_ea, "TOC");
}

//--------------------------------------------------------------------------
static NORETURN void bad_packed_data(void)
{
  loader_failure("Illegal compressed data");
}

//--------------------------------------------------------------------------
static uint32 read_number(const uchar *&packed, const uchar *end)
{
  uint32 arg = 0;
  for ( int i=0; ; i++ )
  {
    if ( packed >= end )
      bad_packed_data();
    uchar b = *packed++;
    arg <<= 7;
    arg |= (b & 0x7F);
    if ( (b & 0x80) == 0 )
      break;
    if ( i > 4 )
      bad_packed_data();
  }
  return arg;
}

//--------------------------------------------------------------------------
static void unpack_section(
        const bytevec_t &packedvec,
        ea_t start,
        uint32 usize)
{
  bytevec_t unpacked;
  const uchar *packed = packedvec.begin();
  const uchar *pckend = packedvec.begin() + packedvec.size();
  while ( packed < pckend )
  {
    uchar code = *packed++;
    uint32 arg = code & 0x1F;
    if ( arg == 0 )
      arg = read_number(packed, pckend);
    switch ( code >> 5 )
    {
      case 0:           // Zero
        unpacked.growfill(arg);
        break;

      case 1:           // blockCopy
        unpacked.append(packed, arg);
        packed += arg;
        break;

      case 2:           // repeatedBlock
        {
          int32 repeat = read_number(packed, pckend) + 1;
          while ( --repeat >= 0 )
            unpacked.append(packed, arg);
          packed += arg;
        }
        break;

      case 3:           // interleaveRepeatBlockWithBlockCopy
        {
          int32 commonSize  = arg;
          int32 customSize  = read_number(packed, pckend);
          int32 repeatCount = read_number(packed, pckend);
          const uchar *common = packed;
          packed += commonSize;
          while ( --repeatCount >= 0 )
          {
            if ( packed+customSize > pckend )
              bad_packed_data();
            unpacked.append(common, commonSize);
            unpacked.append(packed, customSize);
            packed += customSize;
          }
          unpacked.append(common, commonSize);
        }
        break;

      case 4:           // interleaveRepeatBlockWithZero
        {
          int32 commonSize  = arg;
          int32 customSize  = read_number(packed, pckend);
          int32 repeatCount = read_number(packed, pckend);
          while ( --repeatCount >= 0 )
          {
            if ( packed+customSize > pckend )
              bad_packed_data();
            unpacked.growfill(commonSize);
            unpacked.append(packed, customSize);
            packed += customSize;
          }
          unpacked.growfill(commonSize);
        }
        break;

      default:
        bad_packed_data();
    }
  }
  if ( unpacked.size() < usize )
    unpacked.growfill(usize-unpacked.size());
  if ( unpacked.size() != usize )
    bad_packed_data();
  mem2base(unpacked.begin(), start, start+unpacked.size(), FILEREG_NOTPATCHABLE);
}

//--------------------------------------------------------------------------
static void load_section(
        int i,
        linput_t *li,
        pef_section_t &ps,
        const char *sname,
        const char *classname,
        int is_packed)
{
  uint32 size = ps.totalSize;
  ea_t base  = ps.defaultAddress ? ps.defaultAddress : toEA(inf.baseaddr,0);
  ea_t start = freechunk(base, size, 1-(1 << ps.alignment));
  ea_t end   = start + size;
  if ( is_packed )
  {
    bytevec_t packed;
    packed.resize(ps.packedSize);
    qlseek(li, ps.containerOffset);
    lread(li, packed.begin(), packed.size());
    unpack_section(packed, start, ps.unpackedSize);
  }
  else
  {
    file2base(li, ps.containerOffset,
              start, start+ps.unpackedSize, FILEREG_PATCHABLE);
  }
  set_selector(i+1, 0);
  if ( !add_segm(i+1, start, end, sname, classname) )
    loader_failure();
  ps.defaultAddress = (uint32)start;
}

//--------------------------------------------------------------------------
//
//      load file into the database.
//
void idaapi load_file(linput_t *li, ushort /*neflag*/, const char * /*fileformatname*/)
{
  pef_t pef;
  toc_ea = BADADDR;
  toc.create("$ toc");
  qlseek(li, 0);
  lread(li, &pef, sizeof(pef_t));
  swap_pef(pef);

  if ( strncmp(pef.architecture,PEF_ARCH_PPC,4) == 0 && ph.id != PLFM_PPC )
    set_processor_type("ppc",   SETPROC_ALL|SETPROC_FATAL);
  if ( strncmp(pef.architecture,PEF_ARCH_68K,4) == 0 && ph.id != PLFM_68K )
    set_processor_type("68000", SETPROC_ALL|SETPROC_FATAL);

  // read section headers
  qvector<pef_section_t> sec;
  if ( pef.sectionCount != 0 )
  {
    sec.resize(pef.sectionCount);
    lread(li, sec.begin(), sec.size()*sizeof(pef_section_t));
  }

  // swap section headers and find the loader section
  pef_section_t *loader = NULL;
  for ( int i=0; i < sec.size(); i++ )
  {
    swap_pef_section(sec[i]);
    if ( sec[i].sectionKind == PEF_SEC_LOADER )
      loader = &sec[i];
  }

  int32 snames_table = sizeof(pef_t) + sizeof(pef_section_t)*sec.size();
  for ( int i=0; i < sec.size(); i++ )
  {
    char buf[MAXSTR];
    char *secname = get_string(li, snames_table, sec[i].nameOffset, buf, sizeof(buf));
    switch ( sec[i].sectionKind )
    {
      case PEF_SEC_PDATA :      //   Pattern initialized data segment
        load_section(i, li, sec[i], secname, CLASS_DATA, 1);
        break;
      case PEF_SEC_CODE  :      //   Code segment
      case PEF_SEC_EDATA :      //   Executable data segment
        load_section(i, li, sec[i], secname, CLASS_CODE, 0);
        break;
      case PEF_SEC_DATA  :      //   Unpacked data segment
        load_section(i, li, sec[i], secname,
            sec[i].unpackedSize != 0 ? CLASS_DATA : CLASS_BSS, 0);
        break;
      case PEF_SEC_CONST :      //   Read only data
        load_section(i, li, sec[i], secname, CLASS_CONST, 0);
        break;
      case PEF_SEC_LOADER:      //   Loader section
      case PEF_SEC_DEBUG :      //   Reserved for future use
      case PEF_SEC_EXCEPT:      //   Reserved for future use
      case PEF_SEC_TRACEB:      //   Reserved for future use
        continue;
      default:
        ask_for_feedback("Unknown section type");
        continue;
    }
    if ( i == 0 )
      create_filename_cmt();
    add_long_cmt(sec[i].defaultAddress, 1, "Segment share type: %s\n",
                 get_sec_share_name(sec[i].shareKind, buf, sizeof(buf)));
  }
  if ( loader != NULL )
  {
    bytevec_t ldrdata;
    ldrdata.resize(loader->packedSize);
    qlseek(li, loader->containerOffset);
    lread(li, ldrdata.begin(), ldrdata.size());
    process_loader_data(ldrdata, sec);
  }
}


//--------------------------------------------------------------------------
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
int idaapi accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
  if ( n == 0 && is_pef_file(li) )
  {
    qstrncpy(fileformatname,"PEF (Mac OS or Be OS executable)",MAX_FILE_FORMAT_NAME);
    return 1;
  }
  return 0;
}

//----------------------------------------------------------------------
bool idaapi init_loader_options(linput_t *li)
{
  pef_t pef;
  qlseek(li, 0);
  lread(li, &pef, sizeof(pef_t));
  swap_pef(pef);
  if ( strncmp(pef.architecture,PEF_ARCH_PPC,4) == 0 && ph.id != PLFM_PPC )
    set_processor_type("ppc",   SETPROC_ALL|SETPROC_FATAL);
  if ( strncmp(pef.architecture,PEF_ARCH_68K,4) == 0 && ph.id != PLFM_68K )
    set_processor_type("68000", SETPROC_ALL|SETPROC_FATAL);
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
