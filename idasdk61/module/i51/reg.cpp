/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su, ig@datarescue.com
 *                              FIDO:   2:50620/209
 *
 */

#include "i51.hpp"
#include <entry.hpp>
#include <srarea.hpp>

//--------------------------------------------------------------------------
processor_subtype_t ptype;
ea_t intmem = 0;
ea_t sfrmem = 0;

static const char *RegNames[] =
{
  "A", "AB", "B",
  "R0", "R1", "R2",  "R3",  "R4",  "R5",  "R6",  "R7",
  "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
  "WR0",  "WR2",  "WR4",  "WR6",  "WR8",  "WR10", "WR12", "WR14",
  "WR16", "WR18", "WR20", "WR22", "WR24", "WR26", "WR28", "WR30",
  "DR0",  "DR4",  "DR8",  "DR12", "DR16", "DR20", "DR24", "DR28",
  "DR32", "DR36", "DR40", "DR44", "DR48", "DR52", "DPX",  "SPX",
  "DPTR","C", "PC",
  "cs","ds"
};

//----------------------------------------------------------------------
netnode helper;
char device[MAXSTR] = "";
static size_t numports;
static ioport_t *ports;
static const char cfgname[] = "i51.cfg";

inline void get_cfg_filename(char *buf, size_t bufsize)
{
  qstrncpy(buf, cfgname, bufsize);
}

static ea_t AdditionalSegment(size_t size,size_t offset, const char *name);
#define I8051

#define NO_GET_CFG_PATH
#include "../iocommon.cpp"

//------------------------------------------------------------------
const char *idaapi set_idp_options(const char *keyword,int /*value_type*/,const void * /*value*/)
{
  if ( keyword != NULL )
    return IDPOPT_BADKEY;
  if ( choose_ioport_device(cfgname, device, sizeof(device), parse_area_line0) )
    set_device_name(device, IORESP_PORT|IORESP_INT);
  return IDPOPT_OK;
}

//------------------------------------------------------------------
const ioport_t *find_sym(int address)
{
  return find_ioport(ports, numports, address);
}

const ioport_bit_t *find_bit(ea_t address, int bit)
{
  return find_ioport_bit(ports, numports, address, bit);
}

//----------------------------------------------------------------------
bool IsPredefined(const char *name)
{
  for ( int i=0; i < numports; i++ )
  {
    ioport_t &p = ports[i];
    if ( strcmp(p.name, name) == 0 )
      return true;
    if ( p.bits != NULL )
    {
      for ( int j=0; j < sizeof(ioport_bits_t)/sizeof(ioport_bit_t); j++ )
      {
        const ioport_bit_t *b = (*p.bits)+j;
        if ( b->name != NULL && strcmp(b->name, name) == 0 )
          return true;
      }
    }
  }
  return false;
}

//----------------------------------------------------------------------
//static void apply_symbols(void)
//{
//  for ( int i=0; i < numports; i++ )
//  {
//    ioport_t &p = ports[i];
//    ea_t ea = sfrmem + p.address;
//    ea_t oldea = get_name_ea(BADADDR, p.name);
//    if ( oldea != ea )
//    {
//      if ( oldea != BADADDR ) del_global_name(oldea);
//      do_unknown(ea, DOUNK_EXPAND);
//      set_name(ea, p.name, SN_NOLIST);
//    }
//    if ( p.cmt != NULL ) set_cmt(ea,p.cmt, 1);
//  }
//}

//----------------------------------------------------------------------
struct entry_t
{
  char proc;
  char off;
  const char *name;
  const char *cmt;
};

static const entry_t entries[] =
{
  { prc_51,  0x03, "extint0", "External interrupt 0 (INT0 / EX0)" },
  { prc_51,  0x0B, "timint0", "Timer interrupt 0 (TIM0)" },
  { prc_51,  0x13, "extint1", "External interrupt 1 (INT1 / EX1)" },
  { prc_51,  0x1B, "timint1", "Timer interrupt 1 (TIM1)" },
  { prc_51,  0x23, "serint",  "Serial port interrupt (SERIAL)" },
  { prc_51,  0x2B, "timint2", "Timer interrupt 2 (TIM2) (52 or higher)" },
  { prc_51,  0x33, "pcaint",  "PCA (programmable counter array) interrupt\n(only 51f or higher)" },
  { prc_930, 0x43, "usbhub",  "USB Hub/SOF (isochronous end point) (only 930)" },
  { prc_930, 0x4B, "usbfun",  "USB Function (non-isochronous end point) (only 930)" },
  { prc_930, 0x53, "usbglb",  "USB Global Suspend/Resume and USB Reset (only 930)" },
  { prc_251, 0x7B, "trapint", "TRAP (program interrupt) (only 251 or 930)" }
};

//----------------------------------------------------------------------
// Get linear address of a special segment
//      sel - selector of the segment
static ea_t specialSeg(sel_t sel)
{
  segment_t *s = get_segm_by_sel(sel);
  if ( s != NULL )
  {
    if ( s->type != SEG_IMEM )          // is the segment type correct? - no
    {
      s->type = SEG_IMEM;               // fix it
      s->update();
    }
    return s->startEA;
  }
  return BADADDR;
}

//----------------------------------------------------------------------
static ea_t AdditionalSegment(size_t size, size_t offset, const char *name)
{
  segment_t s;
  s.startEA = (ptype > prc_51)
                   ? (inf.maxEA + 0xF) & ~0xF
                   : freechunk(0, size, 0xF);
  s.endEA   = s.startEA + size;
  s.sel     = allocate_selector((s.startEA-offset) >> 4);
  s.type    = SEG_IMEM;                         // internal memory
  add_segm_ex(&s, name, NULL, ADDSEG_NOSREG|ADDSEG_OR_DIE);
  return s.startEA - offset;
}

//----------------------------------------------------------------------
static void setup_data_segment_pointers(void)
{
  sel_t sel;
  if ( atos("INTMEM",&sel) || atos("RAM", &sel) ) intmem = specialSeg(sel);
  if ( atos("SFR",&sel)    || atos("FSR", &sel) ) sfrmem = specialSeg(sel) - 0x80;
}

//----------------------------------------------------------------------
// The kernel event notifications
// Here you may take desired actions upon some kernel events

static int notify(processor_t::idp_notify msgid, ...)
{
  static int first_time = 1;
  va_list va;
  va_start(va, msgid);

// A well behaving processor module should call invoke_callbacks()
// in his notify() function. If this function returns 0, then
// the processor module should process the notification itself
// Otherwise the code should be returned to the caller:

  int code = invoke_callbacks(HT_IDP, msgid, va);
  if ( code ) return code;

  switch ( msgid )
  {
    case processor_t::init:
      helper.create("$ intel 8051");
      inf.mf = 1;       // Set a big endian mode of the IDA kernel
    default:
      break;

    case processor_t::term:
      free_ioports(ports, numports);
      break;

    case processor_t::newfile:
      {
        segment_t *sptr = get_first_seg();
        if ( sptr != NULL )
        {
          if ( sptr->startEA-get_segm_base(sptr) == 0 )
          {
            inf.beginEA = sptr->startEA;
            inf.startIP = 0;
            for ( int i=0; i < qnumber(entries); i++ )
            {
              if ( entries[i].proc > ptype )
                continue;
              ea_t ea = inf.beginEA+entries[i].off;
              if ( isEnabled(ea) && get_byte(ea) != 0xFF )
              {
                add_entry(ea, ea, entries[i].name, 1);
                set_cmt(ea, entries[i].cmt, 1);
              }
            }
          }
        }
        segment_t *scode = get_first_seg();
        set_segm_class(scode, "CODE");

        if ( ptype > prc_51 )
        {
          AdditionalSegment(0x10000-256-128, 256+128, "RAM");
          if ( scode != NULL )
          {
            ea_t align = (scode->endEA + 0xFFF) & ~0xFFF;
            if ( getseg(align-7) == scode )     // the code segment size is
            {                                   // multiple of 4K or near it
              uchar b0 = get_byte(align-8);
              // 251:
              //  0  : 1-source, 0-binary mode
              //  6,7: must be 1s
              // 82930:
              //  0  : 1-source, 0-binary mode
              //  7  : must be 1s
//              uchar b1 = get_byte(align-7);
              // 251
              //  0: eprommap 0 - FE2000..FE4000 is mapped into 00E000..100000
              //              1 - .............. is not mapped ...............
              //  1: must be 1
              //  3:
              //  2: must be 1
              //  4: intr 1 - upon interrupt PC,PSW are pushed into stack
              //          0 - upon interrupt only PC is pushed into stack
              //  5: must be 1
              //  6: must be 1
              //  7: must be 1
              // 82930:
              //  3: must be 1
              //  5: must be 1
              //  6: must be 1
              //  7: must be 1
//                msg("b0=%x b1=%x\n", b0, b1);
//              if ( (b0 & 0x80) == 0x80 && (b1 & 0xEA) == 0xEA )
              {                         // the init bits are correct
                char pname[sizeof(inf.procName)+1];
                inf.get_proc_name(pname);
                char ntype = (b0 & 1) ? 's' : 'b';
                char *ptr = tail(pname)-1;
                if ( ntype != *ptr
                  && askyn_c(1,
                       "HIDECANCEL\n"
                       "The input file seems to be for the %s mode of the processor. "
                       "Do you want to change the current processor type?",
                       ntype == 's' ? "source" : "binary") > 0 )
                {
                  *ptr = ntype;
                  first_time = 1;
                  set_processor_type(pname, SETPROC_COMPAT);
                }
              }
            }
          }
        }

        // the default data segment will be INTMEM
        {
          segment_t *s = getseg(intmem);
          if ( s != NULL )
            set_default_dataseg(s->sel);
        }

        if ( choose_ioport_device(cfgname, device, sizeof(device), parse_area_line0) )
          set_device_name(device, IORESP_ALL);

        if ( get_segm_by_name("RAM") == NULL )
          AdditionalSegment(256, 0, "RAM");
        if ( get_segm_by_name("FSR") == NULL )
          AdditionalSegment(128, 128, "FSR");
        setup_data_segment_pointers();
      }
      break;

    case processor_t::oldfile:
      setup_data_segment_pointers();
      break;

    case processor_t::newseg:
        // make the default DS point to INTMEM
        // (8051 specific issue)
      {
        segment_t *newseg = va_arg(va, segment_t *);
        segment_t *intseg = getseg(intmem);
        if ( intseg != NULL )
          newseg->defsr[rVds-ph.regFirstSreg] = intseg->sel;
      }
      break;

    case processor_t::newprc:
      {
        processor_subtype_t prcnum = processor_subtype_t(va_arg(va, int));
        if ( !first_time && prcnum != ptype )
        {
          warning("Sorry, it is not possible to change" // (this is 8051 specific)
                  " the processor mode on the fly."
                  " Please reload the input file"
                  " if you want to change the processor.");
          return 0;
        }
        first_time = 0;
        ptype = prcnum;
      }
      break;

    case processor_t::newasm:    // new assembler type
      {
        char buf[MAXSTR];
        if ( helper.supval(-1, buf, sizeof(buf)) > 0 )
          set_device_name(buf, IORESP_NONE);
      }
      break;

    case processor_t::move_segm:// A segment is moved
                                // Fix processor dependent address sensitive information
                                // args: ea_t from - old segment address
                                //       segment_t - moved segment
      {
        // ea_t from    = va_arg(va, ea_t);
        // segment_t *s = va_arg(va, segment_t *);

        // Add commands to adjust your internal variables here
        // Most of the time this callback will be empty
        //
        // If you keep information in a netnode's altval array, you can use
        //      node.altshift(from, s->startEA, s->endEA - s->startEA);
        //
        // If you have a variables pointing to somewhere in the disassembled program memory,
        // you can adjust it like this:
        //
        //      asize_t size = s->endEA - s->startEA;
        //      if ( var >= from && var < from+size )
        //        var += s->startEA - from;
      }
      break;

    case processor_t::is_sane_insn:
                                // is the instruction sane for the current file type?
                                // arg:  int no_crefs
                                // 1: the instruction has no code refs to it.
                                //    ida just tries to convert unexplored bytes
                                //    to an instruction (but there is no other
                                //    reason to convert them into an instruction)
                                // 0: the instruction is created because
                                //    of some coderef, user request or another
                                //    weighty reason.
                                // The instruction is in 'cmd'
                                // returns: 1-ok, <=0-no, the instruction isn't
                                // likely to appear in the program
      {
        int no_crefs = va_arg(va, int);
        return is_sane_insn(no_crefs);
      }
  }
  va_end(va);

  return(1);
}

//-----------------------------------------------------------------------
//      Checkarg data. Common for all assemblers. Not good.
//
//      What is checkarg?
//        It is a possibilty to compare the value of a manually entered
//        operand against its original value.
//        Checkarg is currently implemented for IBM PC, 8051, and PDP-11
//        processors. Other processor are unlikely to be supported.
//      You may just get rid of checkarg and replace the pointers to it
//      in the 'LPH' structure by NULLs.
//
//-----------------------------------------------------------------------
#include "chkarg.cpp"

//-----------------------------------------------------------------------
//                   ASMI
//-----------------------------------------------------------------------
static asm_t asmi = {
  AS_COLON | ASH_HEXF3 | AS_1TEXT | AS_NCHRE | ASO_OCTF1 | AS_RELSUP,
  UAS_PSAM | UAS_NOSEG | UAS_AUBIT | UAS_PBIT | UAS_NOENS,
  "ASMI",
  0,
  NULL,         // no headers
  NULL,         // no bad instructions
  ".equ $, ",
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".text",      // ascii string directive
  ".byte",      // byte directive
  ".word",      // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".byte 0xFF;(array %s)", // uninited arrays
  ".equ",       // equ
  NULL,         // seg prefix
  chkarg_dispatch_i51,
  NULL, NULL,   // FREE
  NULL,
  "$",
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  "%",    // mod
  "&",    // and
  "|",    // or
  "^",    // xor
  "!",    // not
  "<<",   // shl
  ">>",   // shr
  NULL,   // sizeof
};

//-----------------------------------------------------------------------
//                   8051 Macro Assembler   -   Version 4.02a
//                Copyright (C) 1985 by 2500 A.D. Software, Inc.
//-----------------------------------------------------------------------
static asm_t adasm = {
  AS_COLON | ASH_HEXF0 ,
  UAS_PBIT | UAS_SECT,
  "8051 Macro Assembler by 2500 A.D. Software",
  0,
  NULL,         // no headers
  NULL,         // no bad instructions
  "org",
  "end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  "db",         // ascii string directive
  "db",         // byte directive
  "dw",         // word directive
  "long",       // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  "ds %s",      // uninited arrays
  "reg",        // equ
  NULL,         // seg prefix
  chkarg_dispatch_i51,
  NULL, NULL,   // FREE
  NULL,
  "$",
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  NULL,         // mod
  NULL,         // and
  NULL,         // or
  NULL,         // xor
  NULL,         // not
  NULL,         // shl
  NULL,         // shr
  NULL,         // sizeof
  0,            // flag2
  NULL,         // close comment
  COLSTR("<", SCOLOR_SYMBOL) "%s", // low8
  COLSTR(">", SCOLOR_SYMBOL) "%s", // high8
  NULL,         // low16
  NULL,         // high16
};

//-----------------------------------------------------------------------
//      PseudoSam
//-----------------------------------------------------------------------
static const char *ps_headers[] = {
".code",
NULL };

static asm_t pseudosam = {
  AS_COLON | ASH_HEXF1 | AS_N2CHR,
  UAS_PBIT | UAS_PSAM | UAS_SELSG,
  "PseudoSam by PseudoCode",
  0,
  ps_headers,
  NULL,
  ".org",
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".db",        // ascii string directive
  ".db",        // byte directive
  ".dw",        // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".rs %s",     // uninited arrays
  ".equ",       // equ
  NULL,         // seg prefix
  chkarg_dispatch_i51,
  NULL, NULL,   // FREE
  NULL,
  "$",
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  NULL,    // mod
  NULL,    // and
  NULL,    // or
  NULL,    // xor
  NULL,    // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
};

//-----------------------------------------------------------------------
//      Cross-16 assembler definiton
//-----------------------------------------------------------------------
static const char *cross16_headers[] = {
"cpu \"8051.tbl\"",
NULL };

static asm_t cross16 = {
  AS_COLON | ASH_HEXF0 | AS_NHIAS,
  UAS_PBIT | UAS_NOSEG | UAS_NOBIT | UAS_EQCLN,
  "Cross-16 by Universal Cross-Assemblers",
  0,
  cross16_headers,
  NULL,
  "org",
  "end",

  ";",          // comment string
  '"',          // string delimiter
  '\0',         // char delimiter (no char consts)
  "\\\"'",      // special symbols in char and string constants

  "dfb",        // ascii string directive
  "dfb",        // byte directive
  "dwm",        // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  "dfs %s",     // uninited arrays
  "equ",        // Equ
  NULL,         // seg prefix
  chkarg_dispatch_i51,
  NULL, NULL,   // FREE
  NULL,
  "$",
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  NULL,    // mod
  NULL,    // and
  NULL,    // or
  NULL,    // xor
  NULL,    // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
};

//-----------------------------------------------------------------------
//      8051 Cross-Assembler by MetaLink Corporation
//-----------------------------------------------------------------------
static asm_t mcross = {
  AS_COLON | ASH_HEXF0 | AS_NHIAS,
  UAS_NOSEG | UAS_CDSEG | UAS_AUBIT | UAS_NODS | UAS_NOENS,
  "8051 Cross-Assembler by MetaLink Corporation",
  0,
  NULL,
  NULL,
  "org",
  "end",

  ";",          // comment string
  '\'',         // string delimiter
  '\0',         // char delimiter (no char consts)
  "\\\"'",      // special symbols in char and string constants

  "db",         // ascii string directive
  "db",         // byte directive
  "dw",         // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  "ds %s",      // uninited arrays
  "equ",        // Equ
  NULL,         // seg prefix
  chkarg_dispatch_i51,
  NULL, NULL,   // FREE
  NULL,
  "$",
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  NULL,    // mod
  NULL,    // and
  NULL,    // or
  NULL,    // xor
  NULL,    // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
};

//-----------------------------------------------------------------------
//      TASM assembler definiton
//-----------------------------------------------------------------------
static const char *tasm_headers[] = {
".msfirst",
NULL };

static asm_t tasm = {
  AS_COLON | AS_N2CHR | AS_1TEXT,
  UAS_PBIT | UAS_NOENS | UAS_EQCLN | UAS_NOSEG,
  "Table Driven Assembler (TASM) by Speech Technology Inc.",
  0,
  tasm_headers,
  NULL,
  ".org",
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".text",      // ascii string directive
  ".db",        // byte directive
  ".dw",        // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".block %s",  // uninited arrays
  ".equ",
  NULL,         // seg prefix
  chkarg_dispatch_i51,
  NULL, NULL,   // FREE
  NULL,
  "$",
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  NULL,    // mod
  "and",   // and
  "or",    // or
  NULL,    // xor
  "not",   // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
};

static asm_t *asms[] = { &asmi, &adasm, &pseudosam, &cross16, &mcross, &tasm, NULL };
//-----------------------------------------------------------------------
// The short and long names of the supported processors
// The short names must match
// the names in the module DESCRIPTION in the makefile (the
// description is copied in the offset 0x80 in the result DLL)

static const char *shnames[] =
{
  "8051",
  "80251b",
  "80251s",
  "80930b",
  "80930s",
  NULL
};

static const char *lnames[] =
{
  "Intel 8051",
  "Intel 80251 in binary mode",
  "Intel 80251 in source mode",
  "Intel 80930 in binary mode",
  "Intel 80930 in source mode",
  NULL
};

//--------------------------------------------------------------------------
// Opcodes of "return" instructions. This information will be used in 2 ways:
//      - if an instruction has the "return" opcode, its autogenerated label
//        will be "locret" rather than "loc".
//      - IDA will use the first "return" opcode to create empty subroutines.

static uchar retcode_1[] = { 0x22 };
static uchar retcode_2[] = { 0x32 };

static bytes_t retcodes[] = {
 { sizeof(retcode_1), retcode_1 },
 { sizeof(retcode_2), retcode_2 },
 { 0, NULL }                            // NULL terminated array
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,// version
  PLFM_8051,            // id
  PR_RNAMESOK           // can use register names for byte names
  |PR_SEGTRANS          // segment translation is supported (codeSeg)
  |PR_BINMEM,           // The module creates RAM/ROM segments for binary files
                        // (the kernel shouldn't ask the user about their sizes and addresses)
  8,                    // 8 bits in a byte for code segments
  8,                    // 8 bits in a byte for other segments

  shnames,              // array of short processor names
                        // the short names are used to specify the processor
                        // with the -p command line switch)
  lnames,               // array of long processor names
                        // the long names are used to build the processor type
                        // selection menu

  asms,                 // array of target assemblers

  notify,               // the kernel event notification callback

  header,               // generate the disassembly header
  footer,               // generate the disassembly footer

  segstart,             // generate a segment declaration (start of segment)
  std_gen_segm_footer,  // generate a segment footer (end of segment)

  NULL,                 // generate 'assume' directives

  ana,                  // analyze an instruction and fill the 'cmd' structure
  emu,                  // emulate an instruction

  out,                  // generate a text representation of an instruction
  outop,                // generate a text representation of an operand
  i51_data,             // generate a text representation of a data item
  NULL,                 // compare operands
  NULL,                 // can an operand have a type?

  qnumber(RegNames),    // Number of registers
  RegNames,             // Regsiter names
  NULL,                 // get abstract register

  0,                    // Number of register files
  NULL,                 // Register file names
  NULL,                 // Register descriptions
  NULL,                 // Pointer to CPU registers

  rVcs,rVds,
  0,                    // size of a segment register
  rVcs,rVds,

  NULL,                 // No known code start sequences
  retcodes,

  0,I51_last,
  Instructions,

  NULL,                 // int  (*is_far_jump)(int icode);
  NULL,                 // Translation function for offsets
  0,                    // int tbyte_size;  -- doesn't exist
  NULL,                 // int (*realcvt)(void *m, ushort *e, ushort swt);
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  NULL,                 // int (*is_switch)(switch_info_t *si);
  NULL,                 // long (*gen_map_file)(FILE *fp);
  NULL,                 // ea_t (*extract_address)(ea_t ea,const char *string,int x);
  NULL,                 // int (*is_sp_based)(op_t &x);
  NULL,                 // int (*create_func_frame)(func_t *pfn);
  NULL,                 // int (*get_frame_retsize(func_t *pfn)
  NULL,                 // void (*gen_stkvar_def)(char *buf,const member_t *mptr,sval_t v);
  gen_spcdef,           // Generate text representation of an item in a special segment
  I51_ret,              // Icode of return instruction. It is ok to give any of possible return instructions
  set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
  NULL,                 // int (*is_align_insn)(ea_t ea);
  NULL,                 // mvm_t *mvm;

};
