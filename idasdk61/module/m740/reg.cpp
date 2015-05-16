
#include "m740.hpp"

#include <entry.hpp>
#include <srarea.hpp>

// The netnode helper.
// Using this node we will save current configuration information in the
// IDA database.
static netnode helper;

// 740 registers names
static const char *RegNames[] = {
    "A",                // accumulator
    "X",                // index register X
    "Y",                // index register Y
    "S",                // stack pointer
    "PS",               // processor status register
    "cs", "ds"          // these 2 registers are required by the IDA kernel
};

static size_t numports = 0;
static ioport_t *ports = NULL;
char device[MAXSTR] = "";

// include IO common routines (such as set_device_name, apply_config_file, etc..)
#include "../iocommon.cpp"

// returns a pointer to a ioport_t object if address was found in the config file.
// otherwise, returns NULL.
const ioport_t *find_sym(int address) {
    return find_ioport(ports, numports, address);
}

const char *idaapi set_idp_options(
    const char *keyword,
    int /*value_type*/,
    const void * /*value*/ )
{
    if ( keyword != NULL )
        return IDPOPT_BADKEY;

    char cfgfile[QMAXFILE];
    get_cfg_filename(cfgfile, sizeof(cfgfile));
    if ( !choose_ioport_device(cfgfile, device, sizeof(device), NULL) )
    {
      if ( strcmp(device, NONEPROC) == 0 )
        warning("No devices are defined in the configuration file %s", cfgfile);
    }
    else
        set_device_name(device, IORESP_ALL);

    return IDPOPT_OK;
}

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
        case processor_t::init:
            helper.create("$ m740");
        default:
            break;

        case processor_t::term:
            free_ioports(ports, numports);
            break;

        case processor_t::newfile:
            set_idp_options(NULL, 0, NULL);
            break;

        case processor_t::oldfile:
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

    "BYT",        // ascii string directive
    "BYT",        // byte directive (alias: DB)
    NULL,         // word directive (alias: DW)
    NULL,         // dword  (4 bytes, alias: DD)
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

static asm_t iar_asm = {
    AS_COLON |
    ASH_HEXF4 |        // hex $123 format
    ASB_BINF3 |        // bin 0b010 format
    ASO_OCTF5 |        // oct 123q format
    AS_1TEXT,          // 1 text per line, no bytes
    UAS_RSEG,
    "IAR 740 Assembler",
    0,
    NULL,         // no headers
    NULL,         // no bad instructions
    "ORG",        // origin directive
    "END",        // end directive
    ";",          // comment string
    '"',          // string delimiter
    '\'',         // char delimiter
    "\\\"'",      // special symbols in char and string constants

    "BYTE",       // ascii string directive
    "BYTE",       // byte directive (alias: DB)
    "WORD",       // word directive (alias: DW)
    "DWORD",      // dword  (4 bytes, alias: DD)
    NULL,         // qword  (8 bytes)
    NULL,         // oword  (16 bytes)
    NULL,         // float  (4 bytes)
    NULL,         // double (8 bytes)
    NULL,         // tbyte  (10/12 bytes)
    NULL,         // packed decimal real
    NULL,         // arrays (#h,#d,#v,#s(...)
    "BLKB %s",     // uninited arrays
    "EQU",        // Equ
    NULL,         // seg prefix
    NULL,         // checkarg_preline()
    NULL,         // checkarg_atomprefix()
    NULL,         // checkarg_operations()
    NULL,         // translation to use in character & string constants
    "$",          // current IP (instruction pointer) symbol in assembler
    NULL,         // func_header
    NULL,         // func_footer
    "PUBLIC",     // public
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
static asm_t *asms[] = { &as_asm, &iar_asm, NULL };

// Short and long name for our module

static const char *shnames[] = {
    "m740",
    NULL
};

static const char *lnames[] = {
    "Mitsubishi 8-BIT 740 family",
    NULL
};

static uchar retcode_1[] = { 0x40 };    // rti
static uchar retcode_2[] = { 0x60 };    // rts

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
      PLFM_M740,            // id
      PR_RNAMESOK           // can use register names for byte names
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

      gen_segm_header,      // generate a segment declaration (start of segment)
      std_gen_segm_footer,  // generate a segment footer (end of segment)

      NULL,                 // generate 'assume' directives

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

      rVcs,rVds,
      0,                    // size of a segment register
      rVcs,rVds,

      NULL,                 // No known code start sequences
      retcodes,

      0, m740_last,
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
      NULL,                 // int (*create_func_frame)(func_t *pfn);
      NULL,                 // int (*get_frame_retsize(func_t *pfn)
      NULL,                 // void (*gen_stkvar_def)(char *buf,const member_t *mptr,int32 v);
      gen_spcdef,           // Generate text representation of an item in a special segment
      m740_rts,             // Icode of return instruction. It is ok to give any of possible return instructions
      set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
      NULL,                 // int (*is_align_insn)(ea_t ea);
      NULL                  // mvm_t *mvm;
};
