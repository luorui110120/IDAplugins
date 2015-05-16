
// read elf symbols

#include <fpro.h>
#include <kernwin.hpp>
#include <diskio.hpp>
#include "../../ldr/elf/elfbase.h"
#include "../../ldr/elf/elf.h"
#include "debmod.h"
#include "symelf.hpp"

#define NO_ERRSTRUCT
#define errstruct() warning("bad input file structure")
#define nomem       error

#include "../../ldr/elf/common.cpp"

inline uint32 low(uint32 x) { return x; }

uval_t imagebase;

//--------------------------------------------------------------------------
static int handle_symbol(
        linput_t *li,
        int shndx,
        int info,
        uint32 st_name,
        uval_t st_value,
        int namsec,
        symbol_visitor_t &sv)
{
  if ( shndx == SHN_UNDEF
    || shndx == SHN_LOPROC
    || shndx == SHN_HIPROC
    || shndx == SHN_ABS )
  {
    return 0;
  }

  int type = ELF32_ST_TYPE(info);
  if ( type != STT_OBJECT && type != STT_FUNC )
    return 0;

  if ( st_name == 0 )
    return 0;

  if ( imagebase != uval_t(-1) )
    st_value -= imagebase;

  qstring name = load_name2(li, namsec, st_name);
  return sv.visit_symbol(st_value, name.c_str());
}

//--------------------------------------------------------------------------
static int load_symbols32(
        linput_t *li,
        uint32 pos,
        uint32 size,
        int namsec,
        symbol_visitor_t &sv)
{
  int code = 0;
  qlseek(li, pos + sizeof(Elf32_Sym)); // skip _UNDEF
  uint32 cnt = size / sizeof(Elf32_Sym);
  for ( int i = 1; i < cnt && code == 0; i++ )
  {
    Elf32_Sym st;
    if ( lread4bytes(li,          &st.st_name,  mf )
      || lread4bytes(li, (uint32 *)&st.st_value, mf)
      || lread4bytes(li,          &st.st_size,  mf)
      || qlread(li, &st.st_info, 2) != 2
      || lread2bytes(li,          &st.st_shndx, mf) )
    {
      return -1;
    }
    code = handle_symbol(li, st.st_shndx, st.st_info, st.st_name, st.st_value,
                         namsec, sv);
  }
  return code;
}

//--------------------------------------------------------------------------
static int load_symbols32(
        linput_t *li,
        ushort symsec,
        int namsec,
        symbol_visitor_t &sv)
{
  Elf32_Shdr *sh = shdr32+symsec;
  return load_symbols32(li, sh->sh_offset, sh->sh_size, namsec, sv);
}

//--------------------------------------------------------------------------
static int load_symbols64(
        linput_t *li,
        uint32 pos,
        uint32 size,
        int namsec,
        symbol_visitor_t &sv)
{
  int code = 0;
  qlseek(li, pos + sizeof(Elf64_Sym)); // skip _UNDEF
  uint32 cnt = size / sizeof(Elf64_Sym);
  for ( int i = 1; i < cnt && code == 0; i++ )
  {
    Elf64_Sym st;
    if ( lread4bytes(li, &st.st_name,  mf )
      || qlread(li, &st.st_info,  2) != 2
      || lread2bytes(li, &st.st_shndx, mf)
      || lread8bytes(li, &st.st_value, mf)
      || lread8bytes(li, &st.st_size,  mf) )
    {
      return -1;
    }
    code = handle_symbol(li, st.st_shndx, st.st_info, st.st_name, st.st_value,
                         namsec, sv);
  }
  return code;
}

//--------------------------------------------------------------------------
static int load_symbols64(
        linput_t *li,
        ushort symsec,
        ushort namsec,
        symbol_visitor_t &sv)
{
  Elf64_Shdr *sh = shdr64+symsec;
  return load_symbols64(li, low(sh->sh_offset), sh->sh_size, namsec, sv);
}

//--------------------------------------------------------------------------
static bool map_pht32(linput_t *li, uint32 e_phoff, int e_phnum)
{
  imagebase = uval_t(-1);
  qlseek(li, e_phoff);
  for ( int i=0; i < e_phnum; i++ )
  {
    Elf32_Phdr p;
    if ( lread4bytes(li, &p.p_type, mf ) ||
       lread4bytes(li, &p.p_offset, mf) ||
       lread4bytes(li, &p.p_vaddr, mf) ||
       lread4bytes(li, &p.p_paddr, mf) ||
       lread4bytes(li, &p.p_filesz, mf) ||
       lread4bytes(li, &p.p_memsz, mf) ||
       lread4bytes(li, &p.p_flags, mf) ||
       lread4bytes(li, &p.p_align, mf))       return false;
    add_mapping(p.p_offset, p.p_filesz, p.p_vaddr);
    if ( p.p_type == PT_DYNAMIC )
    {
      dyn_offset = p.p_offset;
      dyn_size   = p.p_filesz;
      dyn_link   = -1;
    }

    // base address is the address of the lowest PT_LOAD segement
    if ( p.p_type == PT_LOAD && p.p_vaddr < imagebase )
      imagebase = p.p_vaddr;
  }
  return true;
}

//--------------------------------------------------------------------------
static bool map_pht64(linput_t *li, uint32 e_phoff, int e_phnum)
{
  imagebase = uval_t(-1);
  qlseek(li, e_phoff);
  for ( int i=0; i < e_phnum; i++ )
  {
    Elf64_Phdr p;
    if ( lread4bytes(li, &p.p_type, mf ) ||
       lread4bytes(li, &p.p_flags, mf) ||
       lread8bytes(li, &p.p_offset, mf) ||
       lread8bytes(li, &p.p_vaddr, mf) ||
       lread8bytes(li, &p.p_paddr, mf) ||
       lread8bytes(li, &p.p_filesz, mf) ||
       lread8bytes(li, &p.p_memsz, mf) ||
       lread8bytes(li, &p.p_align, mf))       return false;
    add_mapping(p.p_offset, p.p_filesz, p.p_vaddr);
    if ( p.p_type == PT_DYNAMIC )
    {
      dyn_offset = p.p_offset;
      dyn_size   = p.p_filesz;
      dyn_link   = -1;
    }

    // base address is the address of the lowest PT_LOAD segement
    if ( p.p_type == PT_LOAD && p.p_vaddr < imagebase )
      imagebase = p.p_vaddr;
  }
  return true;
}

//--------------------------------------------------------------------------
static int _load_elf_symbols(linput_t *li, symbol_visitor_t &sv)
{
  init_elf_vars();

  uint8 (&e_ident)[EI_NIDENT] = ehdr.e_ident; // this is a reference, not a copy

  if ( !is_elf_file(li) )
    return -1;

  qlseek(li, 0);
  qlread(li, &e_ident, sizeof(e_ident));
  if ( e_ident[EI_CLASS] != ELFCLASS32 && e_ident[EI_CLASS] != ELFCLASS64 )
  {
//    warning("Unknown elf class %d (should be %d for 32-bit, %d for 64-bit)",
//      e_ident[EI_CLASS], ELFCLASS32, ELFCLASS64);
    return -1;
  }
  if ( e_ident[EI_DATA] != ELFDATA2LSB && e_ident[EI_DATA] != ELFDATA2MSB )
  {
//    warning("Unknown elf byte sex %d (should be %d for LSB, %d for MSB)",
//      e_ident[EI_DATA], ELFDATA2LSB, ELFDATA2MSB);
    return -1;
  }

  elf64 = e_ident[EI_CLASS] == ELFCLASS64;
#ifndef __EA64__
  if ( elf64 )
  {
    // msg("64-bit ELF files are not supported\n");
    return -1;
  }
#endif
  mf    = e_ident[EI_DATA]  == ELFDATA2MSB;

  if ( lread2bytes(li, &ehdr.e_type, mf )
    || lread2bytes(li, &ehdr.e_machine, mf)
    || lread4bytes(li, &ehdr.e_version, mf) )
  {
    return -1;
  }
  if ( !read_uword(li, &ehdr.e_entry )
    || !read_uword(li, &ehdr.e_phoff)
    || !read_uword(li, &ehdr.e_shoff)
    || lread4bytes(li, &ehdr.e_flags,    mf)
    || lread2bytes(li, &ehdr.e_ehsize,   mf)
    || lread2bytes(li, &ehdr.e_phentsize,mf)
    || lread2bytes(li, &ehdr.e_phnum,    mf)
    || lread2bytes(li, &ehdr.e_shentsize,mf)
    || lread2bytes(li, &ehdr.e_shnum,    mf)
    || lread2bytes(li, &ehdr.e_shstrndx, mf)
    || (ehdr.e_shstrndx && ehdr.e_shstrndx >= ehdr.e_shnum) )
  {
    return -1;
  }
  // Sanitize SHT parameters
  const size_t sht_sizeof = elf64 ? sizeof(Elf64_Shdr) : sizeof(Elf32_Shdr);
  if ( ehdr.e_shnum && ehdr.e_shentsize != sht_sizeof )
  {
//    warning("SHT entry size is invalid (should be %d)\n", sht_sizeof);
    ehdr.e_shentsize = sht_sizeof;
  }
  if ( (ehdr.e_shnum == 0) != (ehdr.e_shoff == 0)
    || ehdr.e_shoff + ehdr.e_shnum*sht_sizeof > qlsize(li) )
  {
//    warning("SHT size or offset is invalid");
    ehdr.e_shnum = 0;
  }

  int code = 0;
  dyninfo_t dyninfo;
  if ( ehdr.e_phnum )
  {
    bool ok = elf64 ? map_pht64(li, ehdr.e_phoff, ehdr.e_phnum)
                    : map_pht32(li, ehdr.e_phoff, ehdr.e_phnum);
    if ( !ok )
    {
      code = -1;
      goto ret;
    }
  }

  if ( ehdr.e_shnum && ehdr.e_shentsize )
  {
    if ( elf64 )
    {
      shdr64 = qalloc_array<Elf64_Shdr>(ehdr.e_shnum);
      if ( shdr64 == NULL )
        goto ret;
      load_sht64(li);
      analyze_sht(li, shdr64);
    }
    else
    {
      shdr32 = qalloc_array<Elf32_Shdr>(ehdr.e_shnum);
      if ( shdr32 == NULL )
        goto ret;
      load_sht32(li);
      analyze_sht(li, shdr32);
    }
  }

  if ( dyn_size )
  {
    read_dyninfo(li, dyn_offset, dyn_size, &dyninfo);
    parse_dyninfo(dyninfo);
  }

  if ( int_sec && (sv.velf & VISIT_INTERP) != 0 )
  {
    qstring name = load_name2(li, int_sec, 0);
    code = sv.visit_interp(name.c_str());
    if ( code != 0 )
      goto ret;
  }

  if ( (sv.velf & VISIT_SYMBOLS) != 0 )
  {
    if ( sym_sec || dsm_sec )
    {
      // Loading symbols
      if ( sym_sec )
      {
        if ( elf64 )
          code = load_symbols64(li, sym_sec, str_sec, sv);
        else
          code = load_symbols32(li, sym_sec, str_sec, sv);
      }
      if ( code == 0 && dsm_sec )
      {
        if ( elf64 )
          code = load_symbols64(li, dsm_sec, dst_sec, sv);
        else
          code = load_symbols32(li, dsm_sec, dst_sec, sv);
      }
    }
    else if ( dynsym_size )
    {
      if ( elf64 )
        code = load_symbols64(li, dynsym_off, dynsym_size, -1, sv);
      else
        code = load_symbols32(li, dynsym_off, dynsym_size, -1, sv);
    }
  }

  if ( (sv.velf & VISIT_DYNINFO) != 0 && !dyninfo.empty() )
  {
    int link = dyn_link;
    if ( link == 0 && dsm_sec != 0 )
      link = elf64 ? shdr64[dsm_sec].sh_link
                   : shdr32[dsm_sec].sh_link;

    for ( int i=0; code == 0 && i < dyninfo.size(); i++ )
    {
      qstring name;
      const Elf64_Dyn &dyn = dyninfo[i];
      switch ( dyn.d_tag )
      {
        case DT_SONAME:
        case DT_RPATH:
        case DT_RUNPATH:
        case DT_NEEDED:
          name = load_name2(li, link, dyn.d_un);
          break;
      }
      code = sv.visit_dyninfo(dyn.d_tag, name.c_str(), dyn.d_un);
    }
  }

ret:
  qfree(shdr64);
  qfree(shdr32);
  clear_mappings();
  return code;
}

//--------------------------------------------------------------------------
int load_linput_elf_symbols(linput_t *li, symbol_visitor_t &sv)
{
  if ( li == NULL )
    return -1;
  int code;
  // there is thread unsafe code in elf handling, so use locks
  lock_begin();
  {
    code = _load_elf_symbols(li, sv);
  }
  lock_end();
  close_linput(li);
  return code;
}

//--------------------------------------------------------------------------
int load_elf_symbols(const char *fname, symbol_visitor_t &sv, bool remote)
{
  return load_linput_elf_symbols(open_linput(fname, remote), sv);
}
