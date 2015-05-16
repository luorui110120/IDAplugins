
#include "m7700.hpp"

#include <entry.hpp>
#include <srarea.hpp>

// The netnode helper.
// Using this node we will save current configuration information in the
// IDA database.
static netnode helper;

// Current processor type
processor_subtype_t ptype;

// 740 registers names
static const char *RegNames[] = {
    "A",        // accumulator A
    "B",        // accumulator B
    "X",        // index register X
    "Y",        // index register Y
    "S",        // stack pointer
    "PC",       // program counter
    "PG",       // program bank register
    "DT",       // data bank register
    "PS",       // processor status register
    "DPR",      // direct page register
    "fM",       // data length flag
    "fX",       // index register length flag
    "cs", "ds"  // these 2 registers are required by the IDA kernel
};

static size_t numports = 0;
static ioport_t *ports = NULL;
char device[MAXSTR] = "";
static const char cfgname[] = "m7700.cfg";

inline void get_cfg_filename(char *buf, size_t bufsize)
{
  qstrncpy(buf, cfgname, bufsize);
}

// include IO common routines (such as set_device_name, apply_config_file, etc..)
#define NO_GET_CFG_PATH
#include "../iocommon.cpp"

inline static bool choose_device(TView *[] = NULL, int = 0) {
    bool ok = choose_ioport_device(cfgname, device, sizeof(device), NULL);
    if ( !ok )
        qstrncpy(device, NONEPROC, sizeof(device));
    return ok;
}

const ioport_t *find_sym(ea_t address) {
    return find_ioport(ports, numports, address);
}

const ioport_bit_t *find_bit(ea_t address, size_t bit) {
    return find_ioport_bit(ports, numports, address, bit);
}

static char m7700_help_message[] =
    "AUTOHIDE REGISTRY\n"
    "You have loaded a file for the Mitsubishi 7700 family processor.\n\n"\
    "This processor can be used in two different 'length modes' : 8-bit and 16-bit.\n"\
    "IDA allows to specify the encoding mode for every single instruction.\n"\
    "For this, IDA uses two virtual segment registers : \n"\
    "   - fM, used to specify the data length;\n"\
    "   - fX, used to specify the index register length.\n\n"\
    "Switching their state from 0 to 1 will switch the disassembly from 16-bit to 8-bit.\n"\
    "You can change their value using the 'change segment register value' command\n"\
    "(the canonical hotkey is Alt-G).\n\n"\
    "Note : in the real design, those registers are represented as flags in the\n"\
    "processor status register.\n";

// The kernel event notifications
// Here you may take desired actions upon some kernel events
static int notify(processor_t::idp_notify msgid, ...)
{
    va_list va;
    va_start(va, msgid);

    // A well behavior processor module should call invoke_callbacks()
    // in his notify() function. If this function returns 0, then
    // the processor module should process the notification itself
    // Otherwise the code should be returned to the caller:

    int code = invoke_callbacks(HT_IDP, msgid, va);
    if ( code ) return code;

    switch ( msgid ) {
        case processor_t::newfile:
            helper.create("$ m7700");
            if ( choose_device() )
                set_device_name(device, IORESP_ALL);
            //  Set the default segment register values :
            //      -1 (badsel) for DR
            //      0 for fM and fX
            for ( segment_t *s=get_first_seg(); s != NULL; s=get_next_seg(s->startEA) )
            {
                SetDefaultRegisterValue(s, rDR, BADSEL);
                SetDefaultRegisterValue(s, rfM, 0);
                SetDefaultRegisterValue(s, rfX, 0);
            }
            info(m7700_help_message);
            break;

        case processor_t::term:
            free_ioports(ports, numports);
        default:
            break;

        case processor_t::newprc:
            ptype = processor_subtype_t(va_arg(va, int));
            break;

        case processor_t::setsgr:
          {
            ea_t ea1 = va_arg(va, ea_t);
            ea_t ea2 = va_arg(va, ea_t);
            int reg  = va_arg(va, int);
            sel_t v  = va_arg(va, sel_t);
            sel_t ov = va_arg(va, sel_t);
            if ( (reg == rfM || reg == rfX) && v != ov )
              set_sreg_at_next_code(ea1, ea2, reg, ov);
          }
          break;

        case processor_t::oldfile:
            helper.create("$ m7700");
            {
              char buf[MAXSTR];
              if ( helper.supval(-1, buf, sizeof(buf)) > 0 )
                set_device_name(buf, IORESP_ALL);
            }
            break;

        case processor_t::savebase:
        case processor_t::closebase:
            helper.supset(-1, device);
            break;
    }

    va_end(va);

    return(1);
}

const char *idaapi set_idp_options(
    const char *keyword,
    int /*value_type*/,
    const void * /*value*/ )
{
    if ( keyword != NULL )
        return IDPOPT_BADKEY;

    if ( !choose_ioport_device(cfgname, device, sizeof(device), NULL)
      && strcmp(device, NONEPROC) == 0 )
    {
      warning("No devices are defined in the configuration file %s", cfgname);
    }
    else
    {
      char buf[MAXSTR];
      if ( helper.supval(-1, buf, sizeof(buf)) > 0 )
        set_device_name(buf, IORESP_ALL);
    }
    return IDPOPT_OK;
}

static asm_t as_asm = {
    AS_COLON |
    ASH_HEXF4 |        // hex $123 format
    ASB_BINF3 |        // bin 0b010 format
    ASO_OCTF5 |        // oct 123q format
    AS_1TEXT,          // 1 text per line, no bytes
    UAS_SEGM|UAS_INDX_NOSPACE,
    "Alfred Arnold's Macro Assembler",
    0,
    NULL,         // no headers
    NULL,         // no bad instructions
    "ORG",        // origin directive
    "END",        // end directive
    ";",          // comment string
    '"',          // string delimiter
    '\'',         // char delimiter
    "\\\"'",      // special symbols in char and string constants

    "DB",         // ascii string directive
    "DB",         // byte directive
    "DW",         // word directive
    "DD",         // dword  (4 bytes)
    "DQ",         // qword  (8 bytes)
    NULL,         // oword  (16 bytes)
    NULL,         // float  (4 bytes)
    NULL,         // double (8 bytes)
    "DT",         // tbyte  (10/12 bytes)
    NULL,         // packed decimal real
    NULL,         // arrays (#h,#d,#v,#s(...)
    "dfs %s",     // uninited arrays
    "equ",        // Equ
    NULL,         // seg prefix
    NULL,         // checkarg_preline()
    NULL,         // checkarg_atomprefix()
    NULL,         // checkarg_operations()
    NULL,         // translation to use in character & string constants
    "$",          // current IP (instruction pointer) symbol in assembler
    NULL,         // func_header
    NULL,         // func_footer
    NULL,         // public
    NULL,         // weak
    NULL,         // extrn
    NULL,         // comm
    NULL,         // get_type_name
    NULL,         // align
    '(', ')',     // lbrace, rbrace
    "%",          // mod
    "&",          // and
    "|",          // or
    "^",          // xor
    "!",          // not
    "<<",         // shl
    ">>",         // shr
    NULL,         // sizeof
    0,            // flag2 ???
    NULL,         // comment close string
    NULL,         // low8 op
    NULL,         // high8 op
    NULL,         // low16 op
    NULL          // high16 op
};

//
//  Mitsubishi Macro Assembler for 7700 Family
//

// gets a function's name
static const char *mits_get_func_name(func_t *pfn, char *buf, size_t bufsize)
{
  ea_t ea = pfn->startEA;
  char *const end = buf + bufsize;
  char *ptr = tag_addr(buf, end, ea);

  if ( get_demangled_name(BADADDR, ea,
         ptr, end-ptr,
         inf.long_demnames, DEMNAM_NAME, 0) )
    return buf;
  return NULL;
}

// prints function header
static void idaapi mits_func_header(func_t *pfn)
{
  std_gen_func_header(pfn);

  char buf[MAXSTR];
  const char *name = mits_get_func_name(pfn, buf, sizeof(buf));
  if ( name != NULL )
  {
    printf_line(inf.indent, COLSTR(".FUNC %s", SCOLOR_ASMDIR), name);
    printf_line(0, COLSTR("%s:", SCOLOR_ASMDIR), name);
  }
}

// prints function footer
static void idaapi mits_func_footer(func_t *pfn)
{
  char buf[MAXSTR];
  const char *name = mits_get_func_name(pfn, buf, sizeof(buf));
  if ( name != NULL )
    printf_line(inf.indent, COLSTR(".ENDFUNC %s", SCOLOR_ASMDIR), name);
}

static asm_t mitsubishi_asm = {
    AS_COLON |
    ASH_HEXF0 |        // hex 123h format
    ASB_BINF0 |        // bin 10100011b format
    ASO_OCTF0 |        // oct 123o format
    AS_1TEXT,          // 1 text per line, no bytes
    UAS_END_WITHOUT_LABEL|UAS_DEVICE_DIR|UAS_BITMASK_LIST,
    "Mitsubishi Macro Assembler for 7700 Family",
    0,
    NULL,         // no headers
    NULL,         // no bad instructions
    ".ORG",       // origin directive
    ".END",       // end directive
    ";",          // comment string
    '"',          // string delimiter
    '\'',         // char delimiter
    "\\\"'",      // special symbols in char and string constants

    ".BYTE",       // ascii string directive
    ".BYTE",      // byte directive
    ".WORD",      // word directive
    ".DWORD",     // dword  (4 bytes)
    NULL,         // qword  (8 bytes)
    NULL,         // oword  (16 bytes)
    NULL,         // float  (4 bytes)
    NULL,         // double (8 bytes)
    NULL,         // tbyte  (10/12 bytes)
    NULL,         // packed decimal real
    NULL,         // arrays (#h,#d,#v,#s(...)
    ".BLKB %s",   // uninited arrays
    ".EQU",       // Equ
    NULL,         // seg prefix
    NULL,         // checkarg_preline()
    NULL,         // checkarg_atomprefix()
    NULL,         // checkarg_operations()
    NULL,         // translation to use in character & string constants
    "$",          // current IP (instruction pointer) symbol in assembler
    mits_func_header,    // func_header
    mits_func_footer,    // func_footer
    ".PUB",       // public
    NULL,         // weak
    NULL,         // extrn
    NULL,         // comm
    NULL,         // get_type_name
    NULL,         // align
    '(', ')',     // lbrace, rbrace
    "%",          // mod
    "&",          // and
    "|",          // or
    "^",          // xor
    "!",          // not
    "<<",         // shl
    ">>",         // shr
    "SIZEOF",     // sizeof
    0,            // flag2 ???
    NULL,         // comment close string
    NULL,         // low8 op
    NULL,         // high8 op
    NULL,         // low16 op
    NULL          // high16 op
};

// Supported assemblers
static asm_t *asms[] = { &mitsubishi_asm, &as_asm, NULL };

// Short and long name for our module

static const char *shnames[] = {
    "m7700",
    "m7750",
    NULL
};

static const char *lnames[] = {
    "Mitsubishi 16-BIT 7700 family",
    "Mitsubishi 16-BIT 7700 family (7750 series)",
    NULL
};

static uchar retcode_1[] = { 0x40 };    // rti
static uchar retcode_2[] = { 0x60 };    // rts
static uchar retcode_3[] = { 0x6B };    // rtl

static bytes_t retcodes[] = {
    { sizeof(retcode_1), retcode_1 },
    { sizeof(retcode_2), retcode_2 },
    { sizeof(retcode_3), retcode_3 },
    { 0, NULL }                            // NULL terminated array
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
      IDP_INTERFACE_VERSION,// version
      PLFM_M7700,           // id
      PR_RNAMESOK           // can use register names for byte names
      |PR_BINMEM            // The module creates RAM/ROM segments for binary files
                            // (the kernel shouldn't ask the user about their sizes and addresses)
      |PR_SEGS              // has segment registers?
      |PR_SGROTHER,         // the segment registers don't contain
                            // the segment selectors, something else
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

      gen_segm_header,      // generate a segment declaration (start of segment)
      std_gen_segm_footer,  // generate a segment footer (end of segment)

      gen_assumes,          // generate 'assume' directives

      ana,                  // analyze an instruction and fill the 'cmd' structure
      emu,                  // emulate an instruction

      out,                  // generate a text representation of an instruction
      outop,                // generate a text representation of an operand
      intel_data,           // generate a text representation of a data item
      NULL,                 // compare operands
      NULL,                 // can an operand have a type?

      qnumber(RegNames),    // Number of registers
      RegNames,             // Regsiter names
      NULL,                 // get abstract register

      0,                    // Number of register files
      NULL,                 // Register file names
      NULL,                 // Register descriptions
      NULL,                 // Pointer to CPU registers

      rDR, rVds,
      2,                    // size of a segment register
      rVcs, rVds,

      NULL,                 // No known code start sequences
      retcodes,

      0, m7700_last,
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
      NULL,                 // int (*is_sp_based)(op_t &x);
      create_func_frame,    // int (*create_func_frame)(func_t *pfn);
      idp_get_frame_retsize, // int (*get_frame_retsize(func_t *pfn)
      NULL,                 // void (*gen_stkvar_def)(char *buf,const member_t *mptr,int32 v);
      gen_spcdef,           // Generate text representation of an item in a special segment
      m7700_rts,            // Icode of return instruction. It is ok to give any of possible return instructions
      set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
      NULL,                 // int (*is_align_insn)(ea_t ea);
      NULL                  // mvm_t *mvm;
};
