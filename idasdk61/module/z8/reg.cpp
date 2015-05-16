/*
 *  Interactive disassembler (IDA).
 *  Zilog Z8 module
 *
 */

#include "z8.hpp"

//--------------------------------------------------------------------------

ea_t intmem = 0;

//--------------------------------------------------------------------------

const predefined_t iregs[] =
{
  { 0x00, "p0",    "Port 0" },
  { 0x01, "p1",    "Port 1" },
  { 0x02, "p2",    "Port 2" },
  { 0x03, "p3",    "Port 3" },
  { 0xF0, "sio",   "Serial I/O" },
  { 0xF1, "tmr",   "Timer mode" },
  { 0xF2, "t1",    "Timer/counter 1" },
  { 0xF3, "pre1",  "T1 prescaler" },
  { 0xF4, "t0",    "Timer/counter 0" },
  { 0xF5, "pre0",  "T0 prescaler" },
  { 0xF6, "p2m",   "Port 2 mode" },
  { 0xF7, "p3m",   "Port 3 mode" },
  { 0xF8, "p01m",  "Ports 0-1 mode" },
  { 0xF9, "ipr",   "Interrupt priority register" },
  { 0xFA, "irq",   "Interrupt request register" },
  { 0xFB, "imr",   "Interrupt mask register" },
  { 0xFC, "flags", "Program control flags" },
  { 0xFD, "rp",    "Register pointer" },
  { 0xFE, "gpr",   "General purpose register" },
  { 0xFF, "spl",   "Stack pointer" },
  { 0x00, NULL,    NULL }
};

//--------------------------------------------------------------------------

static const char *RegNames[] =
{
  "R0",  "R1",  "R2",   "R3",   "R4",   "R5",   "R6",   "R7",
  "R8",  "R9",  "R10",  "R11",  "R12",  "R13",  "R14",  "R15",
  "RR0", "RR1", "RR2",  "RR3",  "RR4",  "RR5",  "RR6",  "RR7",
  "RR8", "RR9", "RR10", "RR11", "RR12", "RR13", "RR14", "RR15",
  "cs",  "ds"
};

//----------------------------------------------------------------------

typedef struct
{
  int off;
  const char *name;
  const char *cmt;
} entry_t;

static const entry_t entries[] =
{
  {  0, "irq0", "DAV0, IRQ0, Comparator" },
  {  2, "irq1", "DAV1, IRQ1" },
  {  4, "irq2", "DAV2, IRQ2, TIN, Comparator" },
  {  6, "irq3", "IRQ3, Serial in" },
  {  8, "irq4", "T0, Serial out" },
  { 10, "irq5", "T1" },
};

//----------------------------------------------------------------------

static ea_t specialSeg( sel_t sel )
{
  segment_t *s = get_segm_by_sel( sel );

  if( s != NULL )
  {
    if( s->type != SEG_IMEM )
    {
      s->type = SEG_IMEM;
      s->update();
    }

    return s->startEA;
  }

  return BADADDR;
}

//--------------------------------------------------------------------------

static int notify(processor_t::idp_notify msgid, ...) { // Various messages:
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
      inf.mf = 1;                                 // MSB first
    default:
      break;

    case processor_t::newfile:
      {

        segment_t *sptr = get_first_seg();
        if( sptr != NULL )
        {
          if( sptr->startEA - get_segm_base( sptr ) == 0 )
          {
            inf.beginEA = sptr->startEA + 0xC;
            inf.startIP = 0xC;

            for( int i = 0; i < qnumber(entries); i++ )
            {
              ea_t ea = sptr->startEA + entries[i].off;
              if( isEnabled(ea) )
              {
                doWord( ea, 2 );
// ig: set_op_type - внутренняя функция, ее нельзя использовать
//                set_op_type( ea, offflag(), 0 );
                set_offset( ea, 0, sptr->startEA );
                ea_t ea1 = sptr->startEA + get_word( ea );
                auto_make_proc( ea1 );
                set_name( ea, entries[i].name );
// ig: так получше будет?
                set_cmt( sptr->startEA+get_word(ea), entries[i].cmt, 1 );
              }
            }
          }

          set_segm_class( sptr, "CODE" );
        }

        segment_t s;
        ea_t bottom = toEA( inf.baseaddr, 0 );
        intmem       = s.startEA = freechunk( bottom, 256, 0xF );
        s.endEA      = s.startEA + 256;
        s.sel        = allocate_selector( s.startEA >> 4 );
        s.type       = SEG_IMEM;                    // internal memory
        add_segm_ex( &s, "INTMEM", NULL, ADDSEG_OR_DIE);

        const predefined_t *ptr;
        for( ptr = iregs; ptr->name != NULL; ptr++ )
        {
          ea_t ea = intmem + ptr->addr;
          ea_t oldea = get_name_ea( BADADDR, ptr->name );
          if( oldea != ea )
          {
            if( oldea != BADADDR )    set_name( oldea, NULL );
            do_unknown( ea, DOUNK_EXPAND );
            set_name( ea, ptr->name );
          }
          if( ptr->cmt != NULL )      set_cmt( ea, ptr->cmt, 1 );
        }
      }
      break;

    case processor_t::oldfile:
      sel_t sel;
      if( atos( "INTMEM", &sel) ) intmem = specialSeg(sel);
      break;

    case processor_t::newseg:
      {                 // default DS is equal to CS
        segment_t *sptr = va_arg(va, segment_t *);
        sptr->defsr[rVds-ph.regFirstSreg] = sptr->sel;
      }
  }
  va_end(va);

  return(1);
}

//--------------------------------------------------------------------------

static asm_t Z8asm = {
  AS_COLON,
  0,
  "Zilog Z8 assembler",
  0,
  NULL,
  NULL,
  ".org",
  ".end",

  ";",          // comment string
  '\'',         // string delimiter
  '\0',         // char delimiter (no char consts)
  "\\\"'",      // special symbols in char and string constants

  ".ascii",     // ascii string directive
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
  ".block %s",  // uninited arrays
  ".equ",       // Equ
  NULL,         // seg prefix
//  preline, NULL, operdim,
  NULL, NULL, NULL,
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

static asm_t *asms[] = { &Z8asm, NULL };

//--------------------------------------------------------------------------

static const char *shnames[] = { "Z8", NULL };
static const char *lnames[]  = { "Zilog Z8 MCU", NULL };

//--------------------------------------------------------------------------

static uchar retcode[]  = { 0xAF };   // ret
static uchar iretcode[] = { 0xBF };   // iret

static bytes_t retcodes[] = {
  { sizeof( retcode ),  retcode },
  { sizeof( iretcode ), iretcode },
  { 0, NULL }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
// ig: LPH обязательно должен быть extern "C", иначе модуль невозможно
// собрать ваткомом
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_Z8,                      // id
  PRN_HEX|PR_BINMEM,
  8,                            // 8 bits in a byte for code segments
  8,                            // 8 bits in a byte for other segments

  shnames,    // short processor names (null term)
  lnames,     // long processor names (null term)

  asms,       // array of enabled assemblers

  notify,     // Various messages:

  header,     // produce start of text file
  footer,     // produce end of text file

  segstart,   // produce start of segment
  segend,     // produce end of segment

  NULL,

  ana,
  emu,

  out,
  outop,
  z8_data,    //intel_data,
  NULL,       // compare operands
  NULL,       // can have type

  qnumber(RegNames),    // Number of registers
  RegNames,             // Register names
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

  0, Z8_last,
  Instructions,
  NULL,                 // int  (*is_far_jump)(int icode);
  NULL,                 // Translation function for offsets
  0,                    // int tbyte_size;  -- doesn't exist
  NULL,                 // int (*realcvt)(void *m, ushort *e, ushort swt);
  { 0, 0, 0, 0 },       // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  NULL,                 // int (*is_switch)(switch_info_t *si);
  NULL,                 // int32 (*gen_map_file)(FILE *fp);
  NULL,                 // ea_t (*extract_address)(ea_t ea,const char *string,int x);
  NULL,                 // int (*is_sp_based)(op_t &x); -- always, so leave it NULL
  NULL,                 // int (*create_func_frame)(func_t *pfn);
  NULL,                 // int (*get_frame_retsize(func_t *pfn)
  NULL,                 // void (*gen_stkvar_def)(char *buf,const member_t *mptr,int32 v);
  gen_spcdef,           // Generate text representation of an item in a special segment
};
