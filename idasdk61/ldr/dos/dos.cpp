/*
 *  This Loader Module is written by Ilfak Guilfanov and
 *                        rewriten by Yury Haron
 *
 */
/*
  L O A D E R  for MS-DOS file format's
*/

#include <map>
#include "../idaldr.h"
#include <exehdr.h>
#include <setjmp.h>
#include <typeinf.hpp>
#include "dos_ovr.h"

static const char fn_ovr[] = "MS-DOS executable (perhaps overlayed)",
                  fn_exe[] = "MS-DOS executable (EXE)",
                  fn_drv[] = "MS-DOS SYS-file (perhaps device driver)";
const char e_exe[] = "exe";

static jmp_buf jmpb;

#define R_ss 18         // this comes from module/pc/intel.hpp

//--------------------------------------------------------------------------
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
int idaapi accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
  static int order = 0;

  exehdr E;
  uint32 fLen;

  if ( order >= 4 || n > order )
    return 0;

  fLen = qlsize(li);
  char rf[MAXSTR];
  get_input_file_path(rf, sizeof(rf));
  const char *file_ext = get_file_ext(rf);
  if( file_ext == NULL )
    file_ext = "";

  switch ( order )
  {
    case 0:
      if ( fLen <= sizeof(E) ) {
        order = 3;
        break;
      }
      CASSERT(sizeof(E) >= 16);
      lread(li, &E, sizeof(E));
      if ( (E.exe_ident != EXE_ID && E.exe_ident != EXE_ID2 ) ||
         E.HdrSize*16 < sizeof(E)) {
        order = 2;
        break;
      }
      if ( fLen < E.HdrSize*16  ) return 0;
      if ( E.ReloCnt != 0 )
        if ( E.TablOff + (E.ReloCnt*4) > E.HdrSize*16 ||
            (E.TablOff && E.TablOff < sizeof(E))      ||
             !E.TablOff ) return(0);

      if ( E.CalcEXE_Length( ) >= fLen - E.HdrSize*16
         || (PrepareOverlayType(li, &E) == ovr_noexe)) order = 4;
      ++order;
      qstrncpy(fileformatname, fn_exe, MAX_FILE_FORMAT_NAME);
      return(f_EXE);

    case 1:
      qstrncpy(fileformatname, fn_ovr, MAX_FILE_FORMAT_NAME);
      order = 5;
      return(f_EXE);

    case 2:
    case 3:
      break;

    default:
      return 0;
  }

  if ( ++order == 3 ) {
    if ( !stricmp(file_ext, "sys") || !stricmp(file_ext, "drv") ) {
      qstrncpy(fileformatname, fn_drv, MAX_FILE_FORMAT_NAME);
      return(f_DRV);
    }
    order++;
  }

  if ( !stricmp(file_ext, "com") || !stricmp(file_ext, e_exe) )
  { // com files must be readable
    // on wince, file .exe files are unreadable. we do not want them to
    // be detected as com files
    qlseek(li, 0);
    if ( qlread(li, &fLen, 1) == 1 )
    {
      qstrncpy(fileformatname, "MS-DOS COM-file", MAX_FILE_FORMAT_NAME);
      return(f_COM);
    }
  }
  return(0);
}

//-------------------------------------------------------------------------
NORETURN void errstruct(void)
{
  if ( askyn_c(-1, "HIDECANCEL\n"
                   "Bad file structure or read error. Proceed with the loaded infomration?") <= 0 )
    loader_failure(NULL);
  longjmp(jmpb, 1);
#ifdef __CODEGEARC__
  exit(0); // suppress compiler error
#endif
}

//-------------------------------------------------------------------------
int CheckCtrlBrk(void)
{
  if ( wasBreak() )
  {
    if ( askyn_c(0, "HIDECANCEL\nDo you really want to abort loading?") > 0 )
      loader_failure(NULL);
    clearBreak();
    return(1);
  }
  return(0);
}

//-------------------------------------------------------------------------
void add_segm_by_selector(sel_t base, const char *sclass)
{
  segment_t *ptr = get_segm_by_sel(base);

  if( ptr == NULL || ptr->sel != base )
  {
    ea_t ea = sel2ea(base);
    if ( ea > inf.omaxEA )
      inf.omaxEA = ea;

    segment_t s;
    s.sel     = base;
    s.startEA = sel2ea(base);
    s.endEA   = inf.omaxEA;
    s.align   = saRelByte;
    s.comb    = sclass != NULL && strcmp(sclass, "STACK") == 0 ? scStack : scPub;
    add_segm_ex(&s, NULL, sclass, ADDSEG_NOSREG);
  }
}

//-------------------------------------------------------------------------
//
//      For all addresses in relocation table:
//              add 'delta'
//    if ( dosegs ) then make segments
//
static void doRelocs(int16 delta, bool dosegs, netnode ovr_info)
{
  fixup_data_t fd;

  if ( ovr_info == BADNODE ) return;

  fd.type         = FIXUP_SEG16;
  fd.off          = 0;
  fd.displacement = 0;

  for(ea_t xEA=ovr_info.alt1st(); xEA !=BADADDR; xEA=ovr_info.altnxt(xEA))
  {
    showAddr(xEA);

    int16 curval = get_word(xEA);
    int16 base = ushort(curval + delta);
    put_word(xEA, base);
    fd.sel  = base;
    set_fixup(xEA, &fd);
    if ( dosegs )
      add_segm_by_selector(base, NULL);
    CheckCtrlBrk();
  }
}

//--------------------------------------------------------------------------
static void create_msdos_segments(bool com_mode, netnode ovr_info)
{
//  msg("Creating segments...\n");
  add_segm_by_selector(find_selector(inf.start_cs), CLASS_CODE);
  if ( com_mode ) { // COM/DRV
    set_segm_start(inf.ominEA, inf.ominEA, SEGMOD_KILL);
    inf.minEA = inf.ominEA;

    segment_t *s = getseg(inf.minEA);
    if ( s ) {
      s->set_comorg();    //i display ORG directive
      s->update();
    }
  }
  if ( inf.start_ss != BADSEL && inf.start_ss != inf.start_cs ) {
//   msg("Stack segment at 0x%a\n", inf.start_ss);
    add_segm_by_selector(inf.start_ss, CLASS_STACK);
  }
  else // specify the sp value for the first segment
  {
    SetDefaultRegisterValue(get_segm_by_sel(inf.start_cs), R_ss, inf.start_cs);
  }
  doRelocs(inf.baseaddr, true, ovr_info);

//  msg("Checking that segments for all addresses are created...\n");
  ea_t ea = inf.ominEA;
  for(int i = 0; ea < inf.omaxEA; )
  {
    segment_t *sptr = getnseg(i);
    if ( sptr == NULL || ea < sptr->startEA )
    {
      msg("Dummy segment at 0x%a (next segment at 0x%a)\n", ea,
                              sptr == NULL ? BADADDR : sptr->startEA);
      add_segm_by_selector(unsigned(ea>>4), "DUMMY");
    }
    else
    {
      ea = sptr->endEA;
      if ( !isEnabled(ea) ) ea = nextaddr(ea);
      i++;
    }
  }
}

//--------------------------------------------------------------------------
int pos_read(linput_t *li, uint32 pos, void *buf, size_t size)
{
  qlseek(li, pos);
  return qlread(li, buf, size) != size;
}

//--------------------------------------------------------------------------
static ea_t FindDseg(void)
{
  ea_t dea = toEA(inf.start_cs, inf.startIP);

  if ( get_byte(dea) == 0x9A ) {    // call far
    dea = toEA(ask_selector(get_word(dea+3)), get_word(dea+1));
    inf.strtype = ASCSTR_PASCAL;
  }
//
//      Borland startup
//
  uchar code = get_byte(dea);
  uchar reg = code & 7;
  if(   (code & ~7) == 0xB8                             // mov reg, ????
     && (   (   get_byte(dea+3) == 0x8E
             && ((code=get_byte(dea+4)) & ~7) == 0xD8   // mov ds, reg
             && (code & 7) == reg)
         || (   get_byte(dea+3) == 0x2E                 // mov cs:@DGROUP, reg
             && get_byte(dea+4) == 0x89
             && ((code = get_byte(dea+5)) & 0x8F) == 6
             && ((code>>3) & 7) == reg)))
  {
    segment_t *s = get_segm_by_sel(get_word(dea+1));
    return(s == NULL ? BADADDR : s->startEA);
  }
//
//      Watcom startup
//
  if ( get_byte(dea) == 0xE9 ) {         // jmp ???
    dea = dea + 3 + get_word(dea+1);
    if ( get_byte(dea ) == 0xFB &&       // sti
       get_byte(dea+1) == 0xB9) {     // mov cx, ???
      segment_t *s = get_segm_by_sel(get_word(dea+2));
      return(s == NULL ? BADADDR : s->startEA);
    }
  }
//
//      Generic: find copyright notice
//
  static const char *const copyr[] =
  {
                          " - Copyright",
//                        "Borland C++ - Copyright 1991 Borland Intl.",
//                        "Turbo-C - Copyright (c) 1988 Borland Intl.",
//                        "Turbo C - Copyright 1989 Borland Intl.",
//                        "Turbo C++ - Copyright 1990 Borland Intl.",
//                        "MS Run-Time Library - Copyright (c)",
                          NULL
                         };
  for(const char *const *p=copyr; *p != NULL; p++)
  {
    msg("Looking for '%s'...\n", *p);
    ea_t dataea = bin_search(inf.minEA,
                             inf.maxEA,
                             (uchar *)*p,
                             NULL,
                             strlen(*p),
                             BIN_SEARCH_FORWARD,
                             BIN_SEARCH_CASE);
    if ( dataea != BADADDR) return(dataea );
  }
  return(BADADDR);
}

//--------------------------------------------------------------------------
static void setup_default_ds_register(sel_t ds_value)
{
  segment_t *dseg;

  if ( ds_value != BADSEL )
  {
    dseg = get_segm_by_sel(ds_value);
    goto setname;
  }
  msg("Searching for the data segment...\n");
  switch ( inf.filetype ) {
    case f_EXE:                 // Find default data seg
      {
        ea_t dataea = FindDseg();
        if ( dataea == BADADDR ) return;
        if ( (dseg = getseg(dataea)) == NULL ) return;
      }
      dseg->align = saRelPara;
      ds_value = dseg->sel;
setname:
      set_segm_class(dseg, CLASS_DATA);
      set_segm_name(dseg, "dseg");
      break;
    case f_COM:
      ds_value = find_selector(inf.start_cs);
      break;
    default:
      return;
  }
  msg("Default DS register: 0x%*a\n", 4, ds_value);
  set_default_dataseg(ds_value);
}

//--------------------------------------------------------------------------
//
//      load file into the database.
//
void idaapi load_file(linput_t *li, ushort neflag, const char *fileformatname)
{
  exehdr  E;
  int     type = 0;
  netnode ovr_info = BADNODE;
  sel_t   dseg = BADSEL;
  o_type  ovr_type = ovr_noexe;

  if ( !setjmp(jmpb) )
  {
    if ( ph.id != PLFM_386)
      set_processor_type("80386r", SETPROC_ALL|SETPROC_FATAL );

    if ( !strnicmp(fileformatname,fn_ovr,MAX_FILE_FORMAT_NAME-1) )      type=3;
    else if ( !strnicmp(fileformatname,fn_exe,MAX_FILE_FORMAT_NAME-1) ) type=2;
    else if ( !strnicmp(fileformatname,fn_drv,MAX_FILE_FORMAT_NAME-1) ) type=1;
    else                                                                type=0;

    clearBreak();

    inf.cc.cm &= CM_CC_MASK;
    if ( type < 2 ) { // COM/DRV
      inf.cc.cm |= C_PC_SMALL;
      if ( !type ) {  //f_COM
        inf.startIP = 0x100;
        inf.minEA   = toEA(inf.baseaddr, inf.startIP);
      } else {     //f_DRV
        inf.startIP = BADADDR;
        inf.minEA   = toEA(inf.baseaddr, 0 /*binoff*/);
                                        //binoff has no sense for COM/DRV
      }
      inf.start_cs  = inf.baseaddr;
      inf.corestart = 0;
      inf.fcoresiz  = qlsize(li);
      inf.maxEA = inf.minEA + inf.fcoresiz;
    } else { //EXE (/OVR)
      inf.cc.cm |= C_PC_LARGE;
      lread(li, &E, sizeof(E));
      if ( !E.ReloCnt && askyn_c(1, "HIDECANCEL\nPossibly packed file, continue?") <= 0 )
        loader_failure(NULL);
      inf.start_ss = E.ReloSS;
      inf.start_cs = E.ReloCS;
      inf.startSP = E.ExeSP;
      inf.startIP = E.ExeIP;
      // take into account pointers like FFF0:0100
      // FFF0 should be treated as signed in this case
      if ( inf.start_cs >= 0xFFF0 || inf.start_ss >= 0xFFF0 )
      {
        if ( inf.baseaddr < 0x10 )
          inf.baseaddr = 0x10;
        if ( inf.start_cs >= 0xFFF0 ) inf.start_cs = short(inf.start_cs);
        if ( inf.start_ss >= 0xFFF0 ) inf.start_ss = short(inf.start_ss);
      }
      inf.start_ss += inf.baseaddr;
      inf.start_cs += inf.baseaddr;
      inf.minEA = toEA(inf.baseaddr, 0);
      inf.fcoresiz = E.CalcEXE_Length();

      ovr_info.create(LDR_INFO_NODE);
      ovr_info.set((char *)&E, sizeof(E));

      //i Check for file size
      uint32 fsize = qlsize(li) - E.HdrSize*16;
      if ( inf.fcoresiz > fsize ) inf.fcoresiz = fsize;
      if(type == 2 && inf.fcoresiz < fsize &&
         askyn_c(1, "HIDECANCEL\nThe input file has extra information at the end\n"
                    "\3(tail %Xh, loaded %ah), continue?",
                 fsize, inf.fcoresiz) <= 0) loader_failure(NULL);
      inf.maxEA = inf.minEA + inf.fcoresiz;

      ea_t stackEA = toEA(inf.start_ss, inf.startSP);
      if ( inf.maxEA < stackEA ) inf.maxEA = stackEA;
      msg("Reading relocation table...\n");
      if ( E.ReloCnt ) {
        qlseek(li, E.TablOff);
        for(int i = 0; i < E.ReloCnt; i++) {
          unsigned short buf[2];

          lread(li, buf, sizeof(buf));

          ea_t xEA = toEA((ushort)(inf.baseaddr+buf[1]), buf[0]); //i we need ushort() here!
          if ( xEA >= inf.maxEA) errstruct( );
          ovr_info.altset(xEA, 1);
        }
      }
      inf.corestart = E.HdrSize * 16;
      //i preset variable for overlay loading
      if ( type == 3) ovr_type = PrepareOverlayType(li, &E );
    }
//  next 2 strings for create_msdos_segments & CppOverlays
    inf.ominEA = inf.minEA;
    inf.omaxEA = inf.maxEA;

    file2base(li, uint32(inf.corestart), inf.minEA, inf.minEA + inf.fcoresiz,
              FILEREG_PATCHABLE);

    if ( ovr_type != ovr_cpp )
    {
      if ( type == 3 || (neflag & NEF_SEGS) )
        create_msdos_segments((type <= 1), ovr_info);
      else doRelocs(inf.baseaddr, false, ovr_info);
    }

    create_filename_cmt();
    add_pgm_cmt("Base Address: %ah Range: %ah-%ah Loaded length: %ah",
                inf.baseaddr, inf.minEA, inf.maxEA, inf.fcoresiz);
    if ( type >= 2 )
    { //f_EXE
      linput_t *volatile lio = NULL;
      add_pgm_cmt("Entry Point : %a:%a", inf.start_cs, inf.startIP);
      if ( type == 2 && // E.CalcEXE_Length() < qlsize(li) - E.HdrSize*16 &&
           (lio = CheckExternOverlays()) != NULL )
      {
        ++type;
      }
      if ( type != 3 )
      {
        ovr_info.altset(-1, type); //EXE without overlays
      }
      else switch ( ovr_type )
      {
        case ovr_pascal:
          lio = li;
        case ovr_noexe:
          LoadPascalOverlays(lio);
          if ( ovr_type == ovr_noexe) close_linput(lio );
          break;

        case ovr_cpp:
          dseg = LoadCppOverlays(li);
          doRelocs(inf.baseaddr, false, ovr_info);
          break;

        case ovr_ms:
          dseg = LoadMsOverlays(li, E.Overlay == 0);
          break;
      }
    }
  }

  setup_default_ds_register(dseg);  // former SRcreate()
  if ( dseg != BADSEL && ovr_type == ovr_ms ) {
    segment_t *s = get_segm_by_sel(find_selector(inf.start_cs));
    SetDefaultRegisterValue(s, ph.regDataSreg, s->sel);
  }
  inf.beginEA = (inf.startIP == BADADDR) ? BADADDR :
                              toEA(ask_selector(inf.start_cs), inf.startIP);
  if ( inf.startIP != BADADDR )
  {
    splitSRarea1(inf.beginEA, ph.regDataSreg,
                (type < 2) ? find_selector(inf.start_cs) :  //COM/DRV
                ((get_str_type_code(inf.strtype) == ASCSTR_PASCAL) ? //i set in [srareaovl.cpp]FindDseg
                  getSR(inf.beginEA, ph.regDataSreg) : inf.baseaddr - 0x10),
                SR_autostart, true);
  }

  switch ( inf.filetype ) {
    case f_COM: inf.lowoff = 0x100;
    default:    break;
  }
}

//--------------------------------------------------------------------------
static int expand_file(FILE *fp, uint32 pos)
{
// return(chsize(li, pos) || qfseek(fp, pos, SEEK_SET));
//but qchsize(), which does not fill with zeroes.
  uint32 curpos = qftell(fp);
  if ( curpos > pos) error("dos.ldr: Internal error" );
  while ( curpos < pos) if(qfputc(0, fp) == EOF) return(0 );
                      else ++curpos;
  return(1);
}

//--------------------------------------------------------------------------
//
//  generate binary file.
//
int idaapi save_file(FILE *fp, const char* /*fileformatname*/)
{
  int   retcode;
  uint32 codeoff;
  netnode ovr_info(LDR_INFO_NODE, 0, 0);

  if ( !fp) return(ovr_info == BADNODE || ovr_info.altval(-1) == 2 );

  if ( ovr_info != BADNODE ) { //f_EXE
    exehdr E;
    ovr_info.valobj(&E, sizeof(E));

    if ( qfwrite(fp, &E, sizeof(E)) != sizeof(E)) return(0 );
    if ( E.ReloCnt ) {
      if ( !expand_file(fp, E.TablOff)) return(0 );

      for(uval_t x=ovr_info.alt1st(); x !=BADADDR; x=ovr_info.altnxt(x)) {
        ushort buf[2];

        buf[1] = ushort((x >> 4) - inf.baseaddr);
        buf[0] = ushort(x) & 0xF;
        if ( qfwrite(fp, buf, sizeof(buf)) != sizeof(buf)) return(0 );
      }
    }
    codeoff = E.HdrSize * 16;
    if ( !expand_file(fp, codeoff)) return(0 );
  } else  codeoff = 0; //f_COM, f_DRV

  doRelocs(-inf.baseaddr, 0, ovr_info);
  retcode = base2file(fp, codeoff, inf.ominEA, inf.ominEA+inf.fcoresiz);
  doRelocs(inf.baseaddr, 0, ovr_info);
  return(retcode);
}

//----------------------------------------------------------------------
bool idaapi init_loader_options(linput_t*)
{
  set_processor_type("80386r", SETPROC_ALL|SETPROC_FATAL);
  return true;
}

//----------------------------------------------------------------------
static int idaapi move_segm(ea_t from, ea_t to, asize_t /*size*/, const char * /*fileformatname*/)
{
  // Before relocating, we need all of the relocation entries, which were
  // part of the original executable file and consequently stored in our
  // private loader node.
  netnode ovr_info(LDR_INFO_NODE, 0, 0);
  if ( ovr_info == BADNODE )
  {
    // Can't find our private loader node.
    warning("Couldn't find dos.ldr node.\n");
    return 0;
  }

  if ( from == BADADDR )
  {
    // The entire program is being rebased.
    // In this case, 'to' actually contains a delta value; the number of bytes
    // forward (positive) or backward (negative) that the whole database is
    // being moved.
    int32 delta = to;

    // If the delta is not a multiple of 16 bytes, we can't reliably
    // relocate the executable.
    if ( (delta % 16) != 0 )
    {
      warning("DOS images can only be relocated to 16-byte boundaries.\n");
      return 0;
    }

    // Fixup the relocation entry netnode.  It contains entries that point
    // to locations that needed fixups when the image was located at its
    // old address.  Change the entries so that they point to the appropriate
    // places in the new image location.
    uint32 current_base_paragraph = inf.baseaddr;
    ea_t current_base = current_base_paragraph << 4;
    ea_t new_base = current_base + delta;
    ovr_info.altshift(current_base, new_base, MAXADDR);

    // remember bases for later remapping of segment regs
    std::map<ea_t, ea_t> segmap;

    // Now that the relocation entries point to the correct spots, go fix
    // those spots up so that they point to the correct places.
    doRelocs(delta >> 4, false, ovr_info);

    // IDA has adjusted all segment start and end addresses to cover their
    // new effective address ranges, but we, the loader, must finish the
    // job by rebasing each segment.
    for  ( int i = 0; i < get_segm_qty(); i++ )
    {
      segment_t *seg = getnseg(i);
      ea_t curbase = get_segm_base(seg); // Returns base in EA
      ea_t newbase = curbase + delta;
      set_segm_base(seg, newbase >> 4);  // Expects base in Paragraphs
      segmap[curbase >> 4] = newbase >> 4;
      seg->update();
    }

    //fix up segment registers
    int sr_num =  SRareas.get_area_qty();
    sel_t regs[SREG_NUM];
    //rebase segment registers
    for ( int i = 0; i < sr_num; i++ )
    {
      segreg_t *sr = getnSRarea(i);
      bool update_sr = false;
      for ( int j=0; j < qnumber(regs); j++ )
      {
        regs[j] = sr->reg(ph.regFirstSreg + j);
        if( regs[j] != BADSEL )
        {
          std::map<ea_t, ea_t>::const_iterator p = segmap.find(regs[j]);
          if ( p != segmap.end() )
          {
            regs[j] = p->second;
            update_sr = true;
          }
        }
      }

      if ( update_sr )
      {
        sr->setregs(regs);
        SRareas.update(sr);
      }
    }

    // Record the new image base address.
    inf.baseaddr = new_base >> 4;
    set_imagebase(new_base);
  }

  return 1;
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
  save_file,
//      take care of a moved segment (fix up relocations, for example)
  move_segm,
//      initialize user configurable options based on the input file.
  init_loader_options,
};
//==========================================================================
