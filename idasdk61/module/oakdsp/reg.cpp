
#include "oakdsp.hpp"
#include <diskio.hpp>
#include <entry.hpp>
#include <srarea.hpp>


//--------------------------------------------------------------------------
static const char *register_names[] =
{
  "r0",  "r1",   "r2",   "r3",  "r4",  "r5",    //DAAU Registers
  "rb",                                         //Base Register
  "y",                                          //Input Register
  "st0", "st1",  "st2",                         //Status Registers
  "p",                                          //Output Register
  "pc",                                         //Program Counter
  "sp",                                         //Software Stack Pointer
  "cfgi", "cfgj",                               //DAAU Configuration Registers
  "b0h", "b1h",  "b0l",  "b1l",                 //Accumulator B
  "ext0","ext1", "ext2", "ext3",                //External registers
  "a0",  "a1",   "a0l",  "a1l", "a0h", "a1h",   //Accumulator A
  "lc",                                         //Loop Counter
  "sv",                                         //Shift Value Register
  "x",                                          //Input Register
  "dvm",                                        //Data Value Match Register
  "mixp",                                       //Minimal/Maximal Pointer Register
  "icr",                                        //Internal Configuration Register
  "ps",                                         //Product Shifter Control
  "repc",                                       //Internal Repeat Counter
  "b0",   "b1",                                 //Accumulator B
  "modi", "modj",                               //Modulo Modifier
  "stepi","stepj",                              //Linear (Step) Modifier
  "page",                                       //Short Direct Addressing Mode Page
  "cs","ds",                                    //virtual registers for code and data segments
};

//--------------------------------------------------------------------------
static uchar retcode_0[] = { 0x45, 0xc0 };
static uchar retcode_1[] = { 0x45, 0xd0 };
static uchar retcode_2[] = { 0x45, 0x80 };


static bytes_t retcodes[] =
{
 { sizeof(retcode_0), retcode_0 },
 { sizeof(retcode_1), retcode_1 },
 { sizeof(retcode_2), retcode_2 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      Dsp Group OAK DSP Assembler
//-----------------------------------------------------------------------
static asm_t oakasm =
{
//   AS_ASCIIC
   ASH_HEXF4    // $34
  |ASD_DECF0    // 34
  |ASB_BINF2    // %01010
  |ASO_OCTF1    // 0123
  |AS_COLON
  |AS_N2CHR
  |AS_NCMAS
  |AS_ONEDUP,
  0,
  "Dsp Group OAK DSP Assembler",
  0,
  NULL,         // header lines
  NULL,         // bad instructions
  "org",        // org
  "end",        // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\"'",        // special symbols in char and string constants

  "dc",         // ascii string directive
  "dcb",        // byte directive
  "dc",         // word directive
  NULL,         // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  "bs#s(c,) #d, #v", // arrays (#h,#d,#v,#s(...)
  "ds %s",      // uninited arrays
  "equ",        // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  NULL,         // Pointer to checkarg_preline() function.
  NULL,         // char *(*checkarg_atomprefix)(char *operand,void *res); // if !NULL, is called before each atom
  NULL,         // const char **checkarg_operations;
  NULL,         // translation to use in character and string constants.
  "*",          // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  "global",     // "public" name keyword
  NULL,         // "weak"   name keyword
  "xref",       // "extrn"  name keyword
                // .extern directive requires an explicit object size
  NULL,         // "comm" (communal variable)
  NULL,         // const char *(*get_type_name)(int32 flag,uint32 id);
  NULL,         // "align" keyword
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "~",          // not
  "<<",         // shl
  ">>",         // shr
  NULL,         // sizeof
  AS2_BYTE1CHAR,// One symbol per processor byte
};

//-----------------------------------------------------------------------
//      GNU ASM
//-----------------------------------------------------------------------
static asm_t gas =
{
   AS_ASCIIC
  |ASH_HEXF4    // $34
  |ASD_DECF0    // 34
  |ASB_BINF3    // 0b01010
  |ASO_OCTF1    // 0123
  |AS_COLON
  |AS_N2CHR
  |AS_NCMAS
  |AS_ONEDUP,
  UAS_GNU,
  "GNU-like hypothetical assembler",
  0,
  NULL,         // header lines
  NULL,         // bad instructions
  ".org",       // org
  NULL,         // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\"'",        // special symbols in char and string constants

  ".string",    // ascii string directive
  ".byte",      // byte directive
  ".short",     // word directive
  ".long",      // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  ".ds.#s(b,w,l,d) #d, #v", // arrays (#h,#d,#v,#s(...)
  ".space %s",  // uninited arrays
  "=",          // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  NULL,         // Pointer to checkarg_preline() function.
  NULL,         // char *(*checkarg_atomprefix)(char *operand,void *res); // if !NULL, is called before each atom
  NULL,         // const char **checkarg_operations;
  NULL,         // translation to use in character and string constants.
  ".",          // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  ".global",    // "public" name keyword
  NULL,         // "weak"   name keyword
  ".extern",    // "extrn"  name keyword
                // .extern directive requires an explicit object size
  ".comm",      // "comm" (communal variable)
  NULL,         // const char *(*get_type_name)(int32 flag,uint32 id);
  ".align",     // "align" keyword
  '(', ')',     // lbrace, rbrace
  "mod",        // mod
  "and",        // and
  "or",         // or
  "xor",        // xor
  "not",        // not
  "shl",        // shl
  "shr",        // shr
  NULL,         // sizeof
  AS2_BYTE1CHAR,// One symbol per processor byte
  NULL,         // cmnt2
  NULL,         // low8
  NULL,         // high8
  NULL,         // low16
  NULL,         // high16
  "#include \"%s\"",  // a_include_fmt
};

static asm_t *asms[] = { &oakasm, &gas, NULL };

//----------------------------------------------------------------------
static ea_t AdditionalSegment(size_t size, int offset, const char *name)
{
  segment_t s;
  s.startEA = freechunk(0x1000000, size, 0xF);
  s.endEA   = s.startEA + size;
  s.sel     = allocate_selector((s.startEA-offset) >> 4);
  s.type    = SEG_DATA;
  s.bitness = ph.dnbits > 16;
  add_segm_ex(&s, name, "DATA", ADDSEG_NOSREG|ADDSEG_OR_DIE);
  return s.startEA - offset;
}

inline ea_t get_start(segment_t *s)
{  return s ? s->startEA : BADADDR; }

//--------------------------------------------------------------------------
static ioport_t *ports;
static size_t numports;
char device[MAXSTR];
ea_t xmem = BADADDR;
static int xmemsize = 0x1000;


static const char *idaapi oakdsp_callback(const ioport_t *ports, size_t numports, const char *line);

#define callback oakdsp_callback
#include "../iocommon.cpp"

static const char *idaapi oakdsp_callback(const ioport_t *ports, size_t numports, const char *line)
{
  int size;
  if ( sscanf(line, "XMEMSIZE = %i", &size) == 1 )
  {
    xmemsize = size;
    qsnprintf(deviceparams, sizeof(deviceparams), "XMEM=0x%X", xmemsize);
    return NULL;
  }
  return standard_callback(ports, numports, line);
}

const char *find_port(ea_t address)
{
  const ioport_t *port = find_ioport(ports, numports, address);
  return port ? port->name : NULL;
}

//--------------------------------------------------------------------------
static void create_xmem(void)
{
  if ( xmem == BADADDR )
    xmem = AdditionalSegment(xmemsize, 0, "XMEM");
}

//--------------------------------------------------------------------------
void select_device(const char *dname, int respect_info)
{
  set_device_name(dname, respect_info);

  create_xmem();

  for ( int i=0; i < numports; i++ )
  {
    ioport_t *p = ports + i;
    ea_t ea = xmem + p->address;
    const char *name = p->name;
    ea_t nameea = get_name_ea(BADADDR, name);
    if ( nameea != ea )
    {
      set_name(nameea, "");
      if ( !set_name(ea, name, SN_NOWARN) )
        set_cmt(ea, name, 0);
    }
  }
}

//--------------------------------------------------------------------------
const char *idaapi set_idp_options(const char *keyword,int /*value_type*/,const void * /*value*/)
{
  if ( keyword != NULL ) return IDPOPT_BADKEY;
  char cfgfile[QMAXFILE];
  get_cfg_filename(cfgfile, sizeof(cfgfile));
  if ( choose_ioport_device(cfgfile, device, sizeof(device), NULL) )
    select_device(device, IORESP_INT);
  return IDPOPT_OK;
}

//--------------------------------------------------------------------------
int procnum = -1;
netnode helper;

static int notify(processor_t::idp_notify msgid, ...)
{
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
      helper.create("$ oakdsp");
      init_analyzer();
      init_emu();
      break;

    case processor_t::term:
      free_ioports(ports, numports);
    default:
      break;

    case processor_t::newfile:      // new file loaded
      {
        char cfgfile[QMAXFILE];
        get_cfg_filename(cfgfile, sizeof(cfgfile));
        if ( choose_ioport_device(cfgfile, device, sizeof(device), parse_area_line0) )
          select_device(device, IORESP_AREA|IORESP_INT);
        else
          create_xmem();

        segment_t *s0 = get_first_seg();
        if ( s0 != NULL )
        {
          segment_t *s1 = get_next_seg(s0->startEA);
          for (int i = PAGE; i <= vDS; i++)
          {
            SetDefaultRegisterValue(s0, i, BADSEL);
            SetDefaultRegisterValue(s1, i, BADSEL);
          }
        }
      }
      break;

    case processor_t::oldfile:      // old file loaded
      xmem = get_start(get_segm_by_name("XMEM"));
      {
        char dev[MAXSTR];
        char *pdev = helper.supstr(0, dev, sizeof(dev)) > 0 ? dev : NULL;
        select_device(pdev, IORESP_NONE);
      }
      break;

    case processor_t::savebase:
    case processor_t::closebase:
      helper.supset(0, device);
      break;

    case processor_t::newprc:    // new processor type
      {
        int n = va_arg(va, int);
        if ( procnum == -1 )
        {
          procnum = n;
        }
        else if ( procnum != n )  // can't change the processor type
        {                         // after the initial set up
          warning("Sorry, processor type can not be changed after loading");
          return 0;
        }

      }
      break;

    case processor_t::is_sane_insn:
      return is_sane_insn(va_arg(va, int));

    case processor_t::may_be_func:
                                // can a function start here?
                                // arg: none, the instruction is in 'cmd'
                                // returns: probability 0..100
                                // 'cmd' structure is filled upon the entrace
                                // the idp module is allowed to modify 'cmd'
      return may_be_func();
  }
  va_end(va);
  return 1;
}

//-----------------------------------------------------------------------
// We always return "yes" because of the messy problem that
// there are additional operands with a wrong operand number (always 1)
static bool idaapi can_have_type(op_t &)
{
  return true;
}

//-----------------------------------------------------------------------
static const char *shnames[] =
{
  "oakdsp",
  NULL
};

static const char *lnames[] =
{
  "Dsp Group OAK DSP",
  NULL
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_OAKDSP,                  // id
  PRN_HEX
  | PR_SEGS                     // has segment registers
  | PR_ALIGN                    // data items must be aligned
  | PR_BINMEM                   // module knows about memory organization
  | PR_ALIGN_INSN,              // allow align instructions

  16,                           // 16 bits in a byte for code segments
  16,                           // 16 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  header,
  footer,

  segstart,
  segend,

  assumes,              // generate "assume" directives

  ana,                  // analyze instruction
  emu,                  // emulate instruction

  out,                  // generate text representation of instruction
  outop,                // generate ...                    operand
  oakdsp_data,          // generate ...                    data directive
  NULL,                 // compare operands
  can_have_type,        // can_have_type

  qnumber(register_names), // Number of registers
  register_names,       // Register names
  NULL,                 // get abstract register

  0,                    // Number of register files
  NULL,                 // Register file names
  NULL,                 // Register descriptions
  NULL,                 // Pointer to CPU registers

  PAGE,                 // first
  vDS,                  // last
  1,                    // size of a segment register
  vCS, vDS,

  NULL,                 // No known code start sequences
  retcodes,

  OAK_Dsp_null,
  OAK_Dsp_last,
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
  NULL,                 // int32 (*gen_map_file)(FILE *fp);
  NULL,                 // ea_t (*extract_address)(ea_t ea,const char *string,int x);
  is_sp_based,          // int (*is_sp_based)(op_t &x);
  create_func_frame,    // int (*create_func_frame)(func_t *pfn);
  OAK_get_frame_retsize,// int (*get_frame_retsize(func_t *pfn)
  gen_stkvar_def,       // void (*gen_stkvar_def)(char *buf,const member_t *mptr,int32 v);
  gen_spcdef,           // Generate text representation of an item in a special segment
  OAK_Dsp_ret,          // Icode of return instruction. It is ok to give any of possible return instructions
  set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
  is_align_insn,        // int (*is_align_insn)(ea_t ea);
  NULL,                 // mvm_t *mvm;
};
