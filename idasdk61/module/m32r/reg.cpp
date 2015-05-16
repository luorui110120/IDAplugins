
#include "m32r.hpp"

#include <entry.hpp>
#include <srarea.hpp>
#include <ieee.h>

// The netnode helper.
// Using this node we will save current configuration information in the
// IDA database.
static netnode helper;

// Current configuration parameters
uint32 idpflags;

// Current processor type (prc_m32r or prc_m32rx)
processor_subtype_t ptype;

// m32r register names
const char *RegNames[] = {
    "R0", "R1", "R2", "R3", "R4",
    "R5", "R6", "R7", "R8", "R9",
    "R10", "R11", "R12", "R13", "R14", "R15",
    "CR0", "CR1", "CR2", "CR3", "CR6",
    "PC",
    "A0", "A1",
    "CR4", "CR5", "CR7", "CR8", "CR9",
    "CR10", "CR11", "CR12", "CR13", "CR14", "CR15",
    "cs", "ds" // required by IDA kernel
};

static size_t numports = 0;
static ioport_t *ports = NULL;
char device[MAXSTR] = "";
static char const cfgname[] = "m32r.cfg";

inline void get_cfg_filename(char *buf, size_t bufsize)
{
  qstrncpy(buf, cfgname, bufsize);
}

// include IO common routines (such as set_device_name, apply_config_file, etc..)
#define NO_GET_CFG_PATH
#include "../iocommon.cpp"

static void choose_device(TView *[] = NULL, int = 0) {
    if ( choose_ioport_device(cfgname, device, sizeof(device), NULL) )
        set_device_name(device, IORESP_NONE);
}

// create the netnode helper and fetch idpflags value
inline static uint32 refresh_idpflags(void) {
    helper.create("$ m32r");
    idpflags = (uint32)helper.altval(-1);
    return idpflags;
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
            // this processor is big endian
            inf.mf = 1;
        default:
            break;

        case processor_t::term:
            free_ioports(ports, numports);
            break;

        case processor_t::newfile:
            if ( choose_ioport_device(cfgname, device, sizeof(device), NULL) )
                set_device_name(device, IORESP_ALL);
            // default configuration
            if ( refresh_idpflags() == 0 ) {
                idpflags = 0;
                idpflags |= NETNODE_USE_INSN_SYNTHETIC;
                idpflags |= NETNODE_USE_REG_ALIASES;
            }

            // patch register names according to idpflags
            patch_regnames();
            break;

        case processor_t::newprc:
            ptype = processor_subtype_t(va_arg(va, int));
//            msg("ptype = %s\n", ptype == prc_m32r ? "m32r" : ptype == prc_m32rx ? "m32rx" : "???");
            break;

        case processor_t::oldfile:
            refresh_idpflags();
            {
              char buf[MAXSTR];
              if ( helper.supval(-1, buf, sizeof(buf)) > 0 )
                set_device_name(buf, IORESP_NONE);
            }
            // patch register names according to idpflags
            patch_regnames();
            break;

        case processor_t::savebase:
        case processor_t::closebase:
            // synchronize the database long variable with the current configuration settings
#ifdef DEBUG
            msg("Saving configuration: synthetic insn %s, aliases registers %s\n",
                use_synthetic_insn() ? "true " : "false",
                use_reg_aliases() ? "true" : "false"
            );
#endif
            helper.altset(-1, idpflags);
            helper.supset(-1, device);
            break;
    }

    va_end(va);

    return(1);
}

// This function (called when opening the module related configuration in
// the general options) will create a dialog box asking the end-user if he
// wants to use synthetic instructions and register aliases.
const char *idaapi set_idp_options(
    const char *keyword,
    int /*value_type*/,
    const void * /*value*/ )
{
    short opt_subs = 0;

    if ( keyword != NULL )
        return IDPOPT_BADKEY;

    if ( use_synthetic_insn() )     opt_subs |= 1;
    if ( use_reg_aliases() )        opt_subs |= 2;

    static const char form[] =
        "HELP\n"
        "Mitsubishi 32-Bit (m32r) related options :\n"
        "\n"
        " Use synthetic instructions\n"
        "\n"
        "       If this option is on, IDA will simplify instructions and replace\n"
        "       them by synthetic pseudo-instructions.\n"
        "\n"
        "       For example,\n"
        "\n"
        "           bc     label1            ; 8 bits offset    \n"
        "           bc     label2            ; 24 bits offset   \n"
        "           ldi    r1, #0xF              \n"
        "           ldi    r2, #0x123456         \n"
        "           st     r3, @-sp                             \n"
        "           ld     r4, @sp+                             \n"
        "\n"
        "       will be replaced by\n"
        "\n"
        "           bc.s   label1             \n"
        "           bc.l   label2             \n"
        "           ldi8   r1, #0xF           \n"
        "           ldi24  r2, #0x123456      \n"
        "           push   r3                 \n"
        "           pop    r4                 \n"
        "\n"
        " Use registers aliases\n"
        "\n"
        "       If checked, IDA will use aliases names for the following registers :\n"
        "\n"
        "           r13     -> fp          \n"
        "           r14     -> lr          \n"
        "           r15     -> sp          \n"
        "           cr0     -> psw         \n"
        "           cr1     -> cbr         \n"
        "           cr2     -> spi         \n"
        "           cr3     -> spu         \n"
        "           cr6     -> bpc         \n"
        "\n"
        "ENDHELP\n"
        "m32r related options\n"
        "<##Substitutions"
        "#For example, use bc.s instead of 8-Bit bc instructions#Use ~s~ynthetic instructions:C>"
        "<#For example, use fp instead or r14#Use registers ~a~liases:C>>\n\n\n\n"
        "<~C~hoose device name:B:0::>"
        "\n\n\n";

    AskUsingForm_c(form, &opt_subs, choose_device);

    idpflags = 0;    // reset the configuration
    if ( opt_subs & 1 )    idpflags |= NETNODE_USE_INSN_SYNTHETIC;
    if ( opt_subs & 2 )    idpflags |= NETNODE_USE_REG_ALIASES;

    patch_regnames();

    return IDPOPT_OK;
}

// patch the RegNames[] array according to the use_reg_aliases parameter.
void patch_regnames(void)
{
    RegNames[rR13] = (char *)(use_reg_aliases() ? "fp" : "R13");
    RegNames[rR14] = (char *)(use_reg_aliases() ? "lr" : "R14");
    RegNames[rR15] = (char *)(use_reg_aliases() ? "sp" : "R15");
    RegNames[rCR0] = (char *)(use_reg_aliases() ? "psw" : "CR0");
    RegNames[rCR1] = (char *)(use_reg_aliases() ? "cbr" : "CR1");
    RegNames[rCR2] = (char *)(use_reg_aliases() ? "spi" : "CR2");
    RegNames[rCR3] = (char *)(use_reg_aliases() ? "spu" : "CR3");
    RegNames[rCR6] = (char *)(use_reg_aliases() ? "bpc" : "CR6");
    RegNames[rCR7] = (char *)(use_reg_aliases() ? "fpsr" : "CR7");
}

// returns a pointer to a ioport_t object if address was found in the config file.
// otherwise, returns NULL.
const ioport_t *find_sym(ea_t address) {
    return find_ioport(ports, numports, address);
}

// GNU Assembler description
static asm_t gnu_asm = {
    AS_COLON |
    ASH_HEXF3 |   // hex 0x123 format
    ASB_BINF3 |   // bin 0b010 format
    // don't display the final 0 in string declarations
    AS_ASCIIZ | AS_ASCIIC | AS_1TEXT,
    0,
    "m32r GNU Assembler",
    0,
    NULL,         // no headers
    NULL,         // no bad instructions
    NULL,
    NULL,

    ";",          // comment string
    '"',          // string delimiter
    '\'',         // char delimiter
    "\\\"'",      // special symbols in char and string constants

    ".string",    // ascii string directive
    ".byte",      // byte directive
    ".short",     // word directive
    ".word",      // dword  (4 bytes)
    NULL,         // qword  (8 bytes)
    NULL,         // oword  (16 bytes)

//  Although the M32R/X/D has no hardware floating point,
//  the ‘.float’ and ‘.double ’ directives generate IEEE-format
//  floating-point values for compatibility with other development tools.

    ".float",     // float  (4 bytes)
    ".double",    // double (8 bytes)
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
    ".global",    // public
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
    "LOW(%s)",    // low16 op
    "HIGH(%s)"    // high16 op
};

// As this time, we only support the GNU assembler.
static asm_t *asms[] = { &gnu_asm, NULL };

// Short and long names for our module
static const char *shnames[] = {
    "m32r",
    "m32rx",
    NULL
};
static const char *lnames[] = {
    "Mitsubishi 32-BIT family",
    "Mitsubishi 32-BIT family (extended)",
    NULL
};

// Opcodes of "return" instructions. This information will be used in 2 ways:
//      - if an instruction has the "return" opcode, its autogenerated label
//        will be "locret" rather than "loc".
//      - IDA will use the first "return" opcode to create empty subroutines.

static uchar retcode_1[] = { 0x1F, 0xCE };        // jmp lr
static uchar retcode_2[] = { 0x10, 0xD6 };        // rte

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
      PLFM_M32R,            // id
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
      can_have_type,        // can an operand have a type?

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

      0,m32r_last,
      Instructions,

      NULL,                 // int  (*is_far_jump)(int icode);
      NULL,                 // Translation function for offsets
      0,                    // int tbyte_size;  -- doesn't exist
      ieee_realcvt,         // int (*realcvt)(void *m, ushort *e, ushort swt);
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
      m32r_get_frame_retsize, // int (*get_frame_retsize(func_t *pfn)
      NULL,                 // void (*gen_stkvar_def)(char *buf,const member_t *mptr,int32 v);
      gen_spcdef,           // Generate text representation of an item in a special segment
      m32r_rte,             // Icode of return instruction. It is ok to give any of possible return instructions
      set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
      NULL,                 // int (*is_align_insn)(ea_t ea);
      NULL                  // mvm_t *mvm;
};
