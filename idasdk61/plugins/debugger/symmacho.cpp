// read Mach-O symbols

#include <pro.h>
#include <fpro.h>
#include <kernwin.hpp>
#include <diskio.hpp>
#include "../../ldr/mach-o/common.cpp"
#include "symmacho.hpp"

#ifdef __X64__
#define MAGIC   MH_MAGIC_64
#define CPUTYPE CPU_TYPE_X86_64
#define HEADER  mach_header_64
#define CMD_SEGMENT LC_SEGMENT_64
#else
#define MAGIC   MH_MAGIC
#define CPUTYPE CPU_TYPE_I386
#define HEADER  mach_header
#define CMD_SEGMENT LC_SEGMENT
#endif

//--------------------------------------------------------------------------
linput_t *create_mem_input(ea_t start, read_memory_t reader)
{
  struct meminput : generic_linput_t
  {
    ea_t start;
    read_memory_t reader;
    meminput(ea_t _start, read_memory_t _reader) : start(_start), reader(_reader)
    {
      filesize = 0;
      blocksize = 0;
    }
    virtual ssize_t idaapi read(off_t off, void *buffer, size_t nbytes)
    {
      return reader(start+off, buffer, nbytes);
    }
  };
  meminput* pmi = new meminput(start, reader);
  return create_generic_linput(pmi);
}

//--------------------------------------------------------------------------
//parse a mach-o file image in memory and enumerate its segments and symbols
bool parse_macho(ea_t start, linput_t *li, symbol_visitor_t &sv, bool in_mem)
{
  macho_file_t mfile(li);

  if ( !mfile.parse_header() 
    || !mfile.select_subfile(CPUTYPE) )
  {
    msg("Warning: bad file or could not find a member with matching cpu type\n");
    return false;
  }

  // load sections
  const secvec_t &sections   = mfile.get_sections();
  const segcmdvec_t &segcmds = mfile.get_segcmds();

  ea_t expected_base = BADADDR;
  for ( size_t i=0; i < segcmds.size(); i++ )
  {
    const segment_command_64 &sg = segcmds[i];
    if ( is_text_segment(sg) && expected_base == BADADDR )
    {
      expected_base = sg.vmaddr;
      break;
    }
  }

  if ( expected_base == BADADDR )
    return false;

  sval_t slide = start - expected_base;

  // msg("%a: expected base is %a; in_mem = %d\n", start, expected_base, in_mem);

  if ( (sv.velf & VISIT_SEGMENTS) != 0 )
  {
    for ( size_t i=0; i < segcmds.size(); i++ )
    {
      const segment_command_64 &sg = segcmds[i];
      if ( sg.nsects == 0 )
        sv.visit_segment(sg.vmaddr + slide, sg.vmsize, sg.segname);
    }
    for ( size_t i=0; i < sections.size(); i++ )
    {
      const section_64 &sect = sections[i];
      sv.visit_segment(sect.addr + slide, sect.size, sect.sectname);
    }
  }

  if ( (sv.velf & VISIT_SYMBOLS) != 0 )
  {
    nlistvec_t symbols;
    qstring strings;
    mfile.get_symbol_table_info(symbols, strings, in_mem);
    
    // msg("%a: loaded %ld symbols and %ld string bytes\n", start, symbols.size(), strings.size());

    for ( size_t i=0; i < symbols.size(); i++ )
    {
      const struct nlist_64 &nl = symbols[i];
      if ( nl.n_un.n_strx > strings.size() )
        continue;
      const char *name = &strings[nl.n_un.n_strx];

      ea_t ea;
      int type = nl.n_type & N_TYPE;
      switch ( type )
      {
        case N_UNDF:
        case N_PBUD:
        case N_ABS:
          break;
        case N_SECT:
        case N_INDR:
          ea = nl.n_value + slide;
          if ( name[0] != '\0' )
          {
            if ( (nl.n_type & (N_EXT|N_PEXT)) == N_EXT ) // exported
            {
              sv.visit_symbol(ea, name);
            }
            else if ( type == N_SECT && nl.n_sect != NO_SECT ) // private symbols
            {
              sv.visit_symbol(ea, name);
            }
          }
          break;
      }
    }
  }
  return true;
}

//--------------------------------------------------------------------------
//parse a mach-o file image in memory and enumerate its segments and symbols
bool parse_macho_mem(ea_t start, read_memory_t reader, symbol_visitor_t &sv)
{
  linput_t *li = create_mem_input(start, reader);
  if ( li == NULL )
    return false;

  bool ok = parse_macho(start, li, sv, true);

  close_linput(li);
  return ok;
}

//--------------------------------------------------------------------------
asize_t calc_macho_image_size(linput_t *li, ea_t *p_base)
{
  if ( li == NULL )
    return 0;
  if ( p_base != NULL )
    *p_base = BADADDR;

  macho_file_t mfile(li);

  if ( !mfile.parse_header() 
    || !mfile.select_subfile(CPUTYPE) )
  {
    msg("Warning: bad file or could not find a member with matching cpu type\n");
    return 0;
  }

  // load sections
  const segcmdvec_t &segcmds = mfile.get_segcmds();

  ea_t base = BADADDR;
  ea_t maxea = 0;
  for ( size_t i=0; i < segcmds.size(); i++ )
  {
    const segment_command_64 &sg = segcmds[i];
    // since mac os x scatters application segments over the memory
    // we calculate only the text segment size
    if ( is_text_segment(sg) )
    {
      if ( base == BADADDR )
        base = sg.vmaddr;
      ea_t end = sg.vmaddr + sg.vmsize;
      if ( maxea < end )
        maxea = end;
//    msg("segment %s base %a size %d maxea %a\n", sg.segname, sg.vmaddr, sg.vmsize, maxea);
    }
  }
  asize_t size = maxea - base;
  if ( p_base != NULL )
    *p_base = base;
// msg("%s: base %a size %d\n", fname, base, size);
  return size;
}

//--------------------------------------------------------------------------
bool is_dylib_header(ea_t base, read_memory_t read_mem, char *filename, size_t namesize)
{
  HEADER mh;
  if ( read_mem(base, &mh, sizeof(mh)) != sizeof(mh) )
    return false;

  if ( mh.magic != MAGIC || mh.filetype != MH_DYLINKER )
    return false;

  // seems to be dylib
  // find its file name
  filename[0] = '\0';
  ea_t ea = base + sizeof(mh);
  for ( int i=0; i < mh.ncmds; i++ )
  {
    struct load_command lc;
    lc.cmd = 0;
    read_mem(ea, &lc, sizeof(lc));
    if ( lc.cmd == LC_ID_DYLIB )
    {
      struct dylib_command dcmd;
      read_mem(ea, &dcmd, sizeof(dcmd));
      read_mem(ea+dcmd.dylib.name.offset, filename, namesize);
      break;
    }
    else if ( lc.cmd == LC_ID_DYLINKER )
    {
      struct dylinker_command dcmd;
      read_mem(ea, &dcmd, sizeof(dcmd));
      read_mem(ea+dcmd.name.offset, filename, namesize);
      break;
    }
    ea += lc.cmdsize;
  }
  return true;
}
