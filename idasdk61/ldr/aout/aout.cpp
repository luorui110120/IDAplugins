/*
 *  This Loader Module is written by Yury Haron
 *
 */

/*
  L O A D E R  for a.out (Linux)
*/

#include "../idaldr.h"
//#define DEBUG
#include "aout.h"
#include "common.cpp"

class aout
{
public:
  exec  ex;
  bool  msb;
  nlist *symtab;
  uint32 symcount;
  char* strtab;

  uint32 text;    // first address of each section
  uint32 data;
  uint32 bss;
  uint32 extrn;
  uint32 top;     // next available address

  uint32 treloff; // file offset of each section
  uint32 dreloff;
  uint32 symoff;
  uint32 stroff;

  aout(void)
  {
    memset((void*) this, 0, sizeof(*this));
  }
  ~aout()
  {
    if ( symtab != NULL )
      qfree(symtab);
    if ( strtab != NULL )
      qfree(strtab);
  }
};

//--------------------------------------------------------------------------
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
int idaapi accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
  if ( n > 0 )
    return(0);

  int i = get_aout_file_format_index(li);
#ifdef DEBUG
  msg("getfmtindex=%d\n", i);
#endif

  if ( i == 0 ) return 0;

  static const char *const ff[] =
  {
    "demand-paged executable with NULL-ptr check", //q
    "object or impure executable",                 //o
    "demand-paged executable",                     //z
    "core",                                        //c
    "pure executable",                             //n
    "OpenBSD demand-paged executable",             //zo
  };
  qsnprintf(fileformatname, MAX_FILE_FORMAT_NAME, "a.out (%s)", ff[i-1]);
#ifdef DEBUG
  msg("%s\n", fileformatname);
#endif
  return(f_AOUT);
}

//--------------------------------------------------------------------------
static void create32(
        ushort sel,
        ea_t startEA,
        ea_t endEA,
        const char *name,
        const char *classname)
{
  set_selector(sel, 0);
  if ( !add_segm(sel, startEA, endEA, name, classname)) loader_failure( );
  if ( ph.id == PLFM_386) set_segm_addressing(getseg(startEA), 1 );
}

//--------------------------------------------------------------------------
bool ana_hdr(linput_t *li, exec &ex)
{
  bool msb = false;
  lread(li, &ex, sizeof(ex));

  if ( N_BADMAG(ex) )
  {
    swap_exec(ex);
    msb = true;
    msg("Assuming big-endian...\n");
  }
  if ( N_MACHTYPE(ex) ) switch ( N_MACHTYPE(ex) ) {
      case M_386:
      case M_386_NETBSD:
        if ( ph.id != PLFM_386) set_processor_type("80386r", SETPROC_ALL|SETPROC_FATAL );
        break;

      case M_ARM:
      case M_ARM6_NETBSD:
        if ( ph.id != PLFM_ARM) set_processor_type("arm", SETPROC_ALL|SETPROC_FATAL );
        break;

      case M_SPARC:
        if ( ph.id != PLFM_SPARC) set_processor_type("sparcb", SETPROC_ALL|SETPROC_FATAL );
        // set SPARC_V8 parameter
        ph.notify(processor_t::idp_notify(processor_t::loader+1), true);
        break;

      default:
        loader_failure("Unsupported or unknown machine type");
  }
  else if( ph.id != PLFM_386 )
  {
    warning("Missing machine type. Continue?");
  }
  return msb;
}



//--------------------------------------------------------------------------
void do_fixup(uint32 where, uint32 delta, uint32 target, int type, int external)
{
  fixup_data_t fd;
  fd.type = (uchar)type;
  if ( external )
    fd.type |= FIXUP_EXTDEF;

  fd.displacement = delta;
  if ( external )
    target -= delta;

  segment_t *s = getseg(target);
  if ( s != NULL )
  {
    fd.sel = (ushort)s->sel;
    fd.off = target - get_segm_base(s);
  }
  else
  {
    fd.sel = 0;
    fd.off = target;
  }
  set_fixup(where, &fd);
}

#define S_MASK(x) ((1 << (x)) - 1)

//----------------------------------------------------------------------
void do_relocation_sparc(linput_t *li, aout &ctx, uint32 off, uint32 len, int seg)
{
    const segment_t *seg_p = getnseg(seg);
    if ( seg_p == NULL )
    {
      msg("relocation data for missing segment %d ignored\n", seg);
      return;
    }
    uint32 base = seg == 1 ? ctx.text : ctx.data;
#ifdef DEBUG
    msg("seg %d base 0x%08X\n", seg, base);
#endif

    // load relocation table
    reloc_info_sparc *reltab;
    uint32 relcount = len / sizeof(reloc_info_sparc);
    if ( relcount == 0 )
      return;
    reltab = qalloc_array<reloc_info_sparc>(relcount);
    if ( reltab == NULL )
    {
        warning("Unable to allocate relocation table for %d entries\n", relcount);
        return;
    }
    qlseek(li, off);
    for (reloc_info_sparc *rel = reltab; rel < reltab + relcount; rel++)
    {
        uint32 temp = 0;
        lread4bytes(li, &rel->r_address, ctx.msb);
        lread4bytes(li, &temp, ctx.msb);
        lread4bytes(li, &rel->r_addend, ctx.msb);
        rel->r_index  = (temp >> 8) & 0x00FFFFFF;
        rel->r_extern = (temp >> 7) & 1;
        rel->r_type   = (reloc_type_sparc) ((temp) & 0x1F);

#ifdef DEBUG
        if ( rel->r_address >= 0x80C8 && rel->r_address <= 0x8200 )
        msg("%08X: index=0x%06X extern=%d type=%02X addend=0x%08X\n",
            rel->r_address, rel->r_index, rel->r_extern, rel->r_type, rel->r_addend, ph.high_fixup_bits);
#endif
    }


    // perform relocation
    for (reloc_info_sparc *rel = reltab; rel < reltab + relcount; rel++)
    {
        uint32 where  = base + rel->r_address;
        uint32 instr  = get_long(where);
        int   type   = FIXUP_OFF32;
        uint32 target = where;
        uint32 value;
        uint32 merged;
#ifdef DEBUG
        value  = instr;
        merged = instr;
#endif

        if ( rel->r_extern )
        {
            if ( rel->r_index >= ctx.symcount )
            {
                msg("%08X: relocation to extern symbol idx %08X out of bounds, ignored", where, rel->r_index);
                continue;
            }
            nlist *sym = &ctx.symtab[rel->r_index];

            // The in-database address for this symbol was set when loading the symtab.
            target = sym->n_value;
            target += rel->r_addend;

/*
            if ( (sym->n_type & N_TYPE ) != N_ABS &&
                (sym->n_type & N_TYPE) != N_COMM)
                target += where;

            if ( (rel->r_type == SPARC_RELOC_PC10 ) ||
                (rel->r_type == SPARC_RELOC_PC22))
                target -= where;
*/
        }
        else
        {
            if ( rel->r_type == SPARC_RELOC_HI22 || rel->r_type == SPARC_RELOC_LO10 )
                target = rel->r_addend;
            if ( seg == 2 && rel->r_type == SPARC_RELOC_32 )
                target = rel->r_addend;
/*
            if ( (rel->r_index == N_TEXT ) ||
                (rel->r_index == N_DATA) ||
                (rel->r_index == N_BSS))
                target = rel->r_addend;
*/
        }

        uint32 delta = 0;
        switch ( rel->r_type )
        {
        case SPARC_RELOC_32:
            value  = instr;
            target += value;
            merged = target;
            break;
        case SPARC_RELOC_WDISP30:
            value = (instr & S_MASK(30));
            target += value;
            merged = (instr & ~S_MASK(30)) | ((target >> 2) & S_MASK(30));
            break;
        case SPARC_RELOC_WDISP22:
            value = (instr & S_MASK(22));
            target += value;
            merged = (instr & ~S_MASK(22)) | ((target >> 2) & S_MASK(22));
            break;
        case SPARC_RELOC_HI22:
            value = (instr & S_MASK(22)) << 10;
            target += value;
            merged = (instr & ~S_MASK(22)) | ((target >> 10) & S_MASK(22));
            delta = 0; //-(target & S_MASK(10));
            type = FIXUP_VHIGH;
            break;
        case SPARC_RELOC_LO10:
            value = (instr & S_MASK(10));
            target += value;
            merged = (instr & ~S_MASK(10)) | ((target) & S_MASK(10));
            type = FIXUP_VLOW;
            break;
        default:
            msg("Unsupported sparc relocation type 0x%02X, ignored\n", rel->r_type);
            continue;
        }

#ifdef DEBUG
//        if ( rel->r_address < 0x300 )
//      msg("%08X: %08X -> %08X (%08X -> %08X)\n", where, instr, merged, value, target);
#endif

        put_long(where, merged);
        do_fixup(where, rel->r_extern ? rel->r_addend : delta, target, type, rel->r_extern);
    }

    qfree(reltab);
}


//----------------------------------------------------------------------
void do_relocation(linput_t *li, aout &ctx, uint32 off, uint32 len, int seg)
{
    switch ( N_MACHTYPE(ctx.ex) )
    {
    case M_SPARC:
        do_relocation_sparc(li, ctx, off, len, seg);
        break;
    default:
        msg("Warning: Relocation in image file not supported yet for this processor\n");
        break;
    }
}


//----------------------------------------------------------------------
void load_syms(linput_t *li, aout &ctx)
{
    // get string table length
    uint32 tabsize = 0;
    qlseek(li, ctx.stroff);
    lread4bytes(li, &tabsize, ctx.msb);
#ifdef DEBUG
    msg("symoff=0x%08x symlen=0x%08x stroff=0x%08x strlen=0x%08x\n",
        ctx.symoff, ctx.ex.a_syms, ctx.stroff, tabsize);
#endif

    // load string table
    char *strtab = (char *)qalloc(tabsize+1);
    if ( strtab == NULL )
    {
        warning("Unable to allocate string table for %d bytes\n", tabsize+1);
        return;
    }
    qlseek(li, ctx.stroff);
    lreadbytes(li, strtab, tabsize, false);
    strtab[tabsize] = '\0'; // make sure a malformed file doesn't have an unterminated string

    // load symbol table
    uint32 extern_count = 0;
    ctx.symcount = ctx.ex.a_syms / sizeof(nlist);
    nlist *symtab = qalloc_array<nlist>(ctx.symcount);
    if ( symtab == 0 )
    {
        warning("Unable to allocate symbol table for %d entries\n", ctx.symcount);
        qfree(strtab);
        return;
    }
    qlseek(li, ctx.symoff);
    for (nlist *sym = symtab; sym < symtab + ctx.symcount; sym++)
    {
        lread4bytes(li, &sym->n_un.n_strx, ctx.msb);
        lreadbytes(li, &sym->n_type, 1, ctx.msb);
        lreadbytes(li, &sym->n_other, 1, ctx.msb);
        lread2bytes(li, &sym->n_desc, ctx.msb);
        lread4bytes(li, &sym->n_value, ctx.msb);

        if ( sym->n_type == N_EXT ) extern_count++;
    }


    // create extern section
    uint32 extern_base = ctx.top;
    if ( extern_count )
    {
        // create new segment
        add_segm(0, extern_base, extern_base + (extern_count * 4), "extern", "XTRN");
        ctx.extrn = extern_base;
        ctx.top += extern_count * 4;
    }


    // import symbols
#ifdef DEBUG
    int i = 0;
#endif
    uint32 i_extern = 0;
    for (nlist *sym = symtab; sym < symtab + ctx.symcount; sym++)
    {
        if ( sym->n_type & N_STAB ) //debug stab info, not a symbol
          continue;

        if ( sym->n_type == N_EXT )
        {
             sym->n_value = extern_base + (i_extern * 4);
             if ( getseg(sym->n_value)) put_long(sym->n_value, 0 );
             i_extern++;
        }

        if ( getseg(sym->n_value) )
        {
                if ( sym->n_un.n_strx < tabsize )
                {
                    set_name(sym->n_value, strtab + sym->n_un.n_strx,
                             (sym->n_type & N_EXT ? SN_PUBLIC : SN_NON_PUBLIC)|SN_NOWARN);
                }
                else
                {
                    msg("%08X: type=0x%02X other=0x%02X desc=0x%04X: bad str offset %08X\n",
                        sym->n_value, sym->n_type, sym->n_other, sym->n_desc,
                        sym->n_un.n_strx);
                }
        }

        if ( (sym->n_type & N_TYPE) == N_ABS )
        {
#ifdef DEBUG
                    msg("%04X: %08X: type=0x%02X other=0x%02X desc=0x%04X: %s\n",
                        i, sym->n_value, sym->n_type, sym->n_other, sym->n_desc,
                        strtab + sym->n_un.n_strx);
#endif
        }
#ifdef DEBUG
        i++;
#endif
    }

    ctx.strtab = strtab;
    ctx.symtab = symtab;
}

//--------------------------------------------------------------------------
static void handle_ld_info(linput_t *li, int diroff, int base)
{

  lddir_t lddir;
  qlseek(li, diroff);
  lread(li, &lddir, sizeof(lddir));

  ld_info_t ldinfo;
  qlseek(li, lddir.ldinfo-base);
  lread(li, &ldinfo, sizeof(ldinfo));

  int nsyms = (ldinfo.strings - ldinfo.symbols) / sizeof(ld_symbol_t);
  qlseek(li, ldinfo.symbols-base);
  for ( int i=0; i < nsyms; i++ )
  {
    ld_symbol_t sym;
    lread(li, &sym, sizeof(sym));

    char name[MAXSTR];
    qlgetz(li, ldinfo.strings + sym.nameoff - base, name, sizeof(name));

    set_name(sym.addr, name);
    if ( (sym.flags & (AOUT_LD_FUNC|AOUT_LD_DEF)) == AOUT_LD_FUNC )
    { // imported function
      put_byte(sym.addr, 0xC3); // return
      if ( sym.addr <= ldinfo.ldentry )
        warning("interr: symbol #%d (%s) is not in the plt", i, name);
    }
  }
}

//--------------------------------------------------------------------------
//
//      load file into the database.
//
void idaapi load_file(linput_t *li, ushort /*neflag*/, const char * /*fileformatname*/)
{
  aout ctx;
  exec &ex = ctx.ex;
  ctx.msb = ana_hdr(li, ex);
  ctx.symtab = 0;
  ctx.symcount = 0;
  ctx.strtab = 0;
  ctx.treloff = N_TRELOFF(ex);
  ctx.dreloff = N_DRELOFF(ex);
  ctx.symoff = N_SYMOFF(ex);
  ctx.stroff = N_STROFF(ex);

  int txtoff = N_TXTOFF(ex);
  int txtadr;

  switch ( ph.id )
  {
  case PLFM_SPARC:
    txtoff = N_TXTOFF_SPARC(ex);
    txtadr = N_TXTADDR_SPARC(ex);
    ctx.treloff = N_TRELOFF_SPARC(ex);
    ctx.dreloff = N_DRELOFF_SPARC(ex);
    ctx.symoff  = N_SYMOFF_SPARC(ex);
    ctx.stroff  = N_STROFF_SPARC(ex);
    break;

  case PLFM_ARM:
    txtadr = N_TXTADDR_ARM(ex);
    break;

  default:
    txtadr = N_TXTADDR(ex);

    switch ( N_MAGIC(ex) ) {
//    case NMAGIC:
//    case CMAGIC:
      default:
        loader_failure("This image type is not supported yet");
        break;

    case ZMAGIC:
      if ( qlsize(li) < ex.a_text + ex.a_data + N_SYMSIZE(ex) + txtoff )
      {
        txtoff = 0;
        txtadr = 0x1000;
      }
      else
        if ( txtoff < 512)
          loader_failure("Size of demand page < size of block");
    case QMAGIC:
      if ( ex.a_text & 0xFFF || ex.a_data & 0xFFF )
                                  loader_failure("Executable is not page aligned");
      break;

    case OMAGIC:
      txtoff = sizeof(ex);
      break;
    }
    break;
  }

//  if ( ex.a_text + ex.a_data == 0) loader_failure("Empty file" );

  inf.baseaddr = 0;

  uint32 base, top;
  top = base = txtadr;
  if ( ex.a_text || ex.a_data )
  {
    top += ex.a_text;
//    msg("txtoff=%d, base=%d top=%d end=%d\n", txtoff, base, top, top+ex.a_data);
    file2base(li, txtoff, base, top + ex.a_data, FILEREG_PATCHABLE);
    if ( ex.a_text )
    {
      create32(1, base, top, NAME_CODE, CLASS_CODE);
      inf.start_cs = 1;
      inf.startIP  = ex.a_entry;
      ctx.text = base;
    }
    if ( ex.a_data )
    {
      base = top;
      create32(2, base, top += ex.a_data, NAME_DATA, CLASS_DATA);
      set_default_dataseg(2);
      ctx.data = base;
    }
  }
  if ( ex.a_bss )
  {
    create32(3, top, top + ex.a_bss, NAME_BSS, CLASS_BSS);
    ctx.bss = top;
  }
  ctx.top = top + ex.a_bss;

  if ( ex.a_syms) load_syms(li, ctx );

  if ( N_TRSIZE(ex)) do_relocation(li, ctx, ctx.treloff, N_TRSIZE(ex), 1 );
  if ( N_DRSIZE(ex)) do_relocation(li, ctx, ctx.dreloff, N_DRSIZE(ex), 2 );

// We come in here for the regular a.out style of shared libraries */
//      ((ex.a_entry & 0xfff) && N_MAGIC(ex) == ZMAGIC) ||
//    return -ENOEXEC;
//  }
// For  QMAGIC, the starting address is 0x20 into the page.  We mask
//   this off to get the starting address for the page */
//  start_addr =  ex.a_entry & 0xfffff000;
//////

  if ( ph.id != PLFM_SPARC && N_FLAGS(ex) & EX_PIC )
    handle_ld_info(li, ex.a_text, txtadr);

  create_filename_cmt();
  add_pgm_cmt("Flag value: %Xh", N_FLAGS(ex));
}

//----------------------------------------------------------------------
bool idaapi init_loader_options(linput_t *li)
{
  exec ex;
  ana_hdr(li, ex);
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
