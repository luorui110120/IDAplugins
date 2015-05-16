/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include <ctype.h>
#include "tms320c55.hpp"
#include <fpro.h>
#include <diskio.hpp>
#include <srarea.hpp>
#include <ieee.h>

//--------------------------------------------------------------------------
static const char *register_names[] =
{
  "AC0",    // Accumulator
  "AC1",    // Accumulator
  "AC2",    // Accumulator
  "AC3",    // Accumulator
  "T0",     // Temporary register
  "T1",     // Temporary register
  "T2",     // Temporary register
  "T3",     // Temporary register
  "AR0",    // Auxiliary register
  "AR1",    // Auxiliary register
  "AR2",    // Auxiliary register
  "AR3",    // Auxiliary register
  "AR4",    // Auxiliary register
  "AR5",    // Auxiliary register
  "AR6",    // Auxiliary register
  "AR7",    // Auxiliary register

  "AC0L",   // Accumulator
  "AC0H",   // Accumulator
  "AC0G",   // Accumulator
  "AC1L",   // Accumulator
  "AC1H",   // Accumulator
  "AC1G",   // Accumulator
  "AC2L",   // Accumulator
  "AC2H",   // Accumulator
  "AC2G",   // Accumulator
  "AC3L",   // Accumulator
  "AC3H",   // Accumulator
  "AC3G",   // Accumulator
  "BK03",   // Circular buffer size register
  "BK47",   // Circular buffer size register
  "BKC",    // Circular buffer size register
  "BRC0",   // Block-repeat counter
  "BRC1",   // Block-repeat counter
  "BRS1",   // BRC1 save register
  "BSA01",  // Circulat buffer start address register
  "BSA23",  // Circulat buffer start address register
  "BSA45",  // Circulat buffer start address register
  "BSA67",  // Circulat buffer start address register
  "BSAC",   // Circulat buffer start address register
  "CDP",    // Coefficient data pointer (low part of XCDP)
  "CDPH",   // High part of XCDP
  "CFCT",   // Control-flow contect register
  "CSR",    // Computed single-repeat register
  "DBIER0", // Debug interrupt enable register
  "DBIER1", // Debug interrupt enable register
  // DP        Data page register (low part of XDP)
  // DPH       High part of XDP
  "IER0",   // Interrupt enable register
  "IER1",   // Interrupt enable register
  "IFR0",   // Interrupt flag register
  "IFR1",   // Interrupt flag register
  "IVPD",
  "IVPH",
  "PC",     // Program counter
  // PDP       Peripheral data page register
  "PMST",
  "REA0",   // Block-repeat end address register
  "REA0L",  // Block-repeat end address register
  "REA0H",  // Block-repeat end address register
  "REA1",   // Block-repeat end address register
  "REA1L",  // Block-repeat end address register
  "REA1H",  // Block-repeat end address register
  "RETA",   // Return address register
  "RPTC",   // Single-repeat counter
  "RSA0",   // Block-repeat start address register
  "RSA0L",  // Block-repeat start address register
  "RSA0H",  // Block-repeat start address register
  "RSA1",   // Block-repeat start address register
  "RSA1L",  // Block-repeat start address register
  "RSA1H",  // Block-repeat start address register
  "SP",     // Data stack pointer
  "SPH",    // High part of XSP and XSSP
  "SSP",    // System stack pointer
  "ST0",    // Status register
  "ST1",    // Status register
  "ST0_55", // Status register
  "ST1_55", // Status register
  "ST2_55", // Status register
  "ST3_55", // Status register
  "TRN0",   // Transition register
  "TRN1",   // Transition register

  "XAR0",   // Extended auxiliary register
  "XAR1",   // Extended auxiliary register
  "XAR2",   // Extended auxiliary register
  "XAR3",   // Extended auxiliary register
  "XAR4",   // Extended auxiliary register
  "XAR5",   // Extended auxiliary register
  "XAR6",   // Extended auxiliary register
  "XAR7",   // Extended auxiliary register

  "XCDP",   // Extended coefficient data pointer
  "XDP",    // Extended data page register
  "XPC",    // Extended program counter
  "XSP",    // Extended data stack pointer
  "XSSP",   // Extended system stack pointer

  // flags
  "ACOV2",
  "ACOV3",
  "TC1",
  "TC2",
  "CARRY",
  "ACOV0",
  "ACOV1",
  "BRAF",
  "XF",
  "HM",
  "INTM",
  "M40",
  "SATD",
  "SXMD",
  "C16",
  "FRCT",
  "C54CM",
  "DBGM",
  "EALLOW",
  "RDM",
  "CDPLC",
  "AR7LC",
  "AR6LC",
  "AR5LC",
  "AR4LC",
  "AR3LC",
  "AR2LC",
  "AR1LC",
  "AR0LC",
  "CAFRZ",
  "CAEN",
  "CACLR",
  "HINT",
  "CBERR",
  "MPNMC",
  "SATA",
  "CLKOFF",
  "SMUL",
  "SST",

  "BORROW",

  // segment registers
  "ARMS",   // AR indirect operands available
  "CPL",    // Compiler mode
  "DP",     // Data page pointer
  "DPH",    // Data page
  "PDP",    // Peripheral data page register
  "cs","ds" // virtual registers for code and data segments
};

//--------------------------------------------------------------------------
static uchar retcode_0[] = { 0x48, 0x04 }; // ret
static uchar retcode_1[] = { 0x48, 0x05 }; // reti

static bytes_t retcodes[] =
{
 { sizeof(retcode_0), retcode_0 },
 { sizeof(retcode_1), retcode_1 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      TMS320C55 ASM
//-----------------------------------------------------------------------
static asm_t masm55 =
{
  AS_COLON|AS_N2CHR|ASH_HEXF0|ASD_DECF0|ASO_OCTF5|ASB_BINF0|AS_ONEDUP,
  0,
  "MASM55",
  0,
  NULL,         // header lines
  NULL,         // no bad instructions
  NULL,         // org
  ".end",       // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

  ".pstring",   // ascii string directive
  "MY_BYTE",    // byte directive
  ".word",      // word directive
  ".long",      // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".space 8*%s",// uninited arrays
  ".asg",       // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  NULL,         // Pointer to checkarg_preline() function.
  NULL,         // char *(*checkarg_atomprefix)(char *operand,void *res); // if !NULL, is called before each atom
  NULL,         // const char **checkarg_operations;
  NULL,         // translation to use in character and string constants.
  "$",          // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  ".global",    // "public" name keyword
  NULL,         // "weak"   name keyword
  ".ref",       // "extrn"  name keyword
  NULL,         // "comm" (communal variable)
  NULL,         // get_type_name
  ".align",     // "align" keyword
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "~",          // not
  "<<",         // shl
  ">>",         // shr
  NULL,         // sizeof
  AS2_STRINV    // invert string byte order
};

static asm_t *asms[] = { &masm55, NULL };

//--------------------------------------------------------------------------
static ioport_t *ports = NULL;
static size_t numports = 0;
char device[MAXSTR] = "";
static const char *cfgname = "tms320c55.cfg";

static void load_symbols(void)
{
  free_ioports(ports, numports);
  ports = read_ioports(&numports, cfgname, device, sizeof(device), NULL);
}

const char *find_sym(ea_t address)
{
  const ioport_t *port = find_ioport(ports, numports, address);
  return port ? port->name : NULL;
}

const ioport_bit_t *find_bits(ea_t address)
{
  const ioport_t *port = find_ioport(ports, numports, address);
  return port ? (*port->bits) : NULL;
}

const char *find_bit(ea_t address, int bit)
{
  const ioport_bit_t *b = find_ioport_bit(ports, numports, address, bit);
  return b ? b->name : NULL;
}

//--------------------------------------------------------------------------
inline void set_device_name(const char *dev)
{
  if ( dev != NULL )
    qstrncpy(device, dev, sizeof(device));
}

//--------------------------------------------------------------------------

netnode helper;
proctype_t ptype = TMS320C55;
ushort idpflags = TMS320C55_IO|TMS320C55_MMR;


static proctype_t ptypes[] =
{
  TMS320C55
};


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
      helper.create("$ tms320c54");
      {
        char buf[MAXSTR];
        if ( helper.supval(0, buf, sizeof(buf)) > 0 )
          set_device_name(buf);
      }
      inf.mf = 1; // MSB first
      break;

    case processor_t::term:
      free_ioports(ports, numports);
    default:
      break;

    case processor_t::newfile:   // new file loaded
      {
        {
          SetDefaultRegisterValue(NULL, ARMS, 0);
          SetDefaultRegisterValue(NULL, CPL, 1);
          for (int i = DP; i <= rVds; i++)
            SetDefaultRegisterValue(NULL, i, 0);
        }
        static const char informations[] =
        {
          "AUTOHIDE REGISTRY\n"
          "Default values of flags and registers:\n"
          "\n"
          "ARMS bit = 0 (DSP mode operands).\n"
          "CPL  bit = 1 (SP direct addressing mode).\n"
          "DP register = 0 (Data Page register)\n"
          "DPH register = 0 (High part of EXTENDED Data Page Register)\n"
          "PDP register = 0 (Peripheral Data Page register)\n"
          "\n"
          "You can change the register values by pressing Alt-G\n"
          "(Edit, Segments, Change segment register value)\n"
        };
        info(informations);
        break;
      }

    case processor_t::oldfile:   // old file loaded
      idpflags = (ushort)helper.altval(-1);
      break;

    case processor_t::closebase:
    case processor_t::savebase:
      helper.altset(-1, idpflags);
      helper.supset(0,  device);
      break;

    case processor_t::newprc:    // new processor type
      {
        ptype = ptypes[va_arg(va, int)];
        switch ( ptype )
        {
          case TMS320C55:
            break;
          default:
            error("interr: setprc");
            break;
        }
        device[0] = '\0';
        load_symbols();
      }
      break;

    case processor_t::newasm:    // new assembler type
      break;

    case processor_t::newseg:    // new segment
      break;

    case processor_t::get_stkvar_scale_factor:
      return 2;
  }
  va_end(va);
  return 1;
}

//--------------------------------------------------------------------------
static void choose_device(TView *[],int)
{
  if ( choose_ioport_device(cfgname, device, sizeof(device), NULL) )
    load_symbols();
}

static const char *idaapi set_idp_options(const char *keyword,int value_type,const void *value)
{
  if ( keyword == NULL )
  {
    static const char form[] =
"HELP\n"
"TMS320C55 specific options Ü\n"
" ßßßßßßßßßßßßßßßßßßßßßß\n"
"\n"
" Use I/O definitions \n"
"\n"
"       If this option is on, IDA will use I/O definitions\n"
"       from the configuration file into a macro instruction.\n"
"\n"
" Detect memory mapped registers \n"
"\n"
"       If this option is on, IDA will replace addresses\n"
"       by an equivalent memory mapped register.\n"
"\n"
"ENDHELP\n"
"TMS320C54 specific options\n"
"\n"
" <Use ~I~/O definitions:C>\n"
" <Detect memory mapped ~r~egisters:C>>\n"
"\n"
" <~C~hoose device name:B:0::>\n"
"\n"
"\n";
    AskUsingForm_c(form, &idpflags, choose_device);
    return IDPOPT_OK;
  }
  else
  {
    if ( value_type != IDPOPT_BIT ) return IDPOPT_BADTYPE;
    if ( strcmp(keyword, "TMS320C55_IO") == 0 )
    {
      setflag(idpflags,TMS320C55_IO,*(int*)value);
      return IDPOPT_OK;
    }
    else if ( strcmp(keyword, "TMS320C55_MMR") == 0 )
    {
      setflag(idpflags,TMS320C55_MMR,*(int*)value);
      return IDPOPT_OK;
    }
    return IDPOPT_BADKEY;
  }
}

//-----------------------------------------------------------------------
static const char *shnames[] =
{ "TMS32055",
  NULL
};
static const char *lnames[] =
{
  "Texas Instruments TMS320C55",
  NULL
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_TMS320C55,
  PRN_HEX | PR_SEGS | PR_SGROTHER | PR_SCALE_STKVARS,
  8,                            // 8 bits in a byte for code segments
  8,                            // 8 bits in a byte for other segments

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
  intel_data,           // generate ...                    data
  NULL,                 // compare operands
  can_have_type,        // can have type

  qnumber(register_names), // Number of registers
  register_names,       // Register names
  NULL,                 // get abstract register

  0,                    // Number of register files
  NULL,                 // Register file names
  NULL,                 // Register descriptions
  NULL,                 // Pointer to CPU registers

  ARMS,                 // first
  rVds,                 // last
  1,                    // size of a segment register
  rVcs, rVds,

  NULL,                 // No known code start sequences
  retcodes,

  TMS320C55_null,
  TMS320C55_last,
  Instructions,

  NULL,                 // int  (*is_far_jump)(int icode);
  NULL,                 // Translation function for offsets
  0,                    // int tbyte_size;  -- doesn't exist
  ieee_realcvt,          // int (*realcvt)(void *m, ushort *e, ushort swt);
  { 0,7,15,19 },        // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  NULL,                 // int (*is_switch)(switch_info_t *si);
  NULL,                 // long (*gen_map_file)(FILE *fp);
  NULL,                 // ulong (*extract_address)(ulong ea,const char *string,int x);
  NULL,                 // Check whether the operand is relative to stack pointer
  create_func_frame,    // create frame of newly created function
  NULL,                 // Get size of function return address in bytes
  gen_stkvar_def,       // void (*gen_stkvar_def)(char *buf,const member_t *mptr,long v);
  gen_spcdef,           // Generate text representation of an item in a special segment
  TMS320C55_ret,        // Icode of return instruction. It is ok to give any of possible return instructions
  set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
  is_align_insn,        // int (*is_align_insn)(ulong ea);
  NULL,                 // mvm_t *mvm;
};
