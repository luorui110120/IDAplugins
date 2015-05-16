
#include "st9.hpp"

#include <entry.hpp>
#include <srarea.hpp>

// The netnode helper.
// Using this node we will save current configuration information in the
// IDA database.
static netnode helper;

// Current configuration parameters
uint32 idpflags;

const char *ConditionCodes[] = {
    "UNKNOWN",
    "f",         // always false
    "t",         // always true
    "c",         // carry
    "nc",        // not carry
    "z",         // zero
    "nz",        // not zero
    "pl",        // plus
    "mi",        // minus
    "ov",        // overflow
    "nov",       // no overflow
    "eq",        // equal
    "ne",        // not equal
    "ge",        // greater than or equal
    "lt",        // less than
    "gt",        // greater than
    "le",        // less than or equal
    "uge",       // unsigned greated than or equal
    "ul",        // unsigned less than
    "ugt",       // unsigned greater than
    "ule"        // unsigned less than or equal
};

// ST9 registers names
static bool dynamic_reg_names = false;
static const char *RegNames[] = {
    "R0",
    "R1",
    "R2",
    "R3",
    "R4",
    "R5",
    "R6",
    "R7",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
    "R16",
    "R17",
    "R18",
    "R19",
    "R20",
    "R21",
    "R22",
    "R23",
    "R24",
    "R25",
    "R26",
    "R27",
    "R28",
    "R29",
    "R30",
    "R31",
    "R32",
    "R33",
    "R34",
    "R35",
    "R36",
    "R37",
    "R38",
    "R39",
    "R40",
    "R41",
    "R42",
    "R43",
    "R44",
    "R45",
    "R46",
    "R47",
    "R48",
    "R49",
    "R50",
    "R51",
    "R52",
    "R53",
    "R54",
    "R55",
    "R56",
    "R57",
    "R58",
    "R59",
    "R60",
    "R61",
    "R62",
    "R63",
    "R64",
    "R65",
    "R66",
    "R67",
    "R68",
    "R69",
    "R70",
    "R71",
    "R72",
    "R73",
    "R74",
    "R75",
    "R76",
    "R77",
    "R78",
    "R79",
    "R80",
    "R81",
    "R82",
    "R83",
    "R84",
    "R85",
    "R86",
    "R87",
    "R88",
    "R89",
    "R90",
    "R91",
    "R92",
    "R93",
    "R94",
    "R95",
    "R96",
    "R97",
    "R98",
    "R99",
    "R100",
    "R101",
    "R102",
    "R103",
    "R104",
    "R105",
    "R106",
    "R107",
    "R108",
    "R109",
    "R110",
    "R111",
    "R112",
    "R113",
    "R114",
    "R115",
    "R116",
    "R117",
    "R118",
    "R119",
    "R120",
    "R121",
    "R122",
    "R123",
    "R124",
    "R125",
    "R126",
    "R127",
    "R128",
    "R129",
    "R130",
    "R131",
    "R132",
    "R133",
    "R134",
    "R135",
    "R136",
    "R137",
    "R138",
    "R139",
    "R140",
    "R141",
    "R142",
    "R143",
    "R144",
    "R145",
    "R146",
    "R147",
    "R148",
    "R149",
    "R150",
    "R151",
    "R152",
    "R153",
    "R154",
    "R155",
    "R156",
    "R157",
    "R158",
    "R159",
    "R160",
    "R161",
    "R162",
    "R163",
    "R164",
    "R165",
    "R166",
    "R167",
    "R168",
    "R169",
    "R170",
    "R171",
    "R172",
    "R173",
    "R174",
    "R175",
    "R176",
    "R177",
    "R178",
    "R179",
    "R180",
    "R181",
    "R182",
    "R183",
    "R184",
    "R185",
    "R186",
    "R187",
    "R188",
    "R189",
    "R190",
    "R191",
    "R192",
    "R193",
    "R194",
    "R195",
    "R196",
    "R197",
    "R198",
    "R199",
    "R200",
    "R201",
    "R202",
    "R203",
    "R204",
    "R205",
    "R206",
    "R207",
    "R208",
    "R209",
    "R210",
    "R211",
    "R212",
    "R213",
    "R214",
    "R215",
    "R216",
    "R217",
    "R218",
    "R219",
    "R220",
    "R221",
    "R222",
    "R223",
    "R224",
    "R225",
    "R226",
    "R227",
    "R228",
    "R229",
    "R230",
    "R231",
    "R232",
    "R233",
    "R234",
    "R235",
    "R236",
    "R237",
    "R238",
    "R239",
    "R240",
    "R241",
    "R242",
    "R243",
    "R244",
    "R245",
    "R246",
    "R247",
    "R248",
    "R249",
    "R250",
    "R251",
    "R252",
    "R253",
    "R254",
    "R255",
    "RR0",
    "RR1",
    "RR2",
    "RR3",
    "RR4",
    "RR5",
    "RR6",
    "RR7",
    "RR8",
    "RR9",
    "RR10",
    "RR11",
    "RR12",
    "RR13",
    "RR14",
    "RR15",
    "RR16",
    "RR17",
    "RR18",
    "RR19",
    "RR20",
    "RR21",
    "RR22",
    "RR23",
    "RR24",
    "RR25",
    "RR26",
    "RR27",
    "RR28",
    "RR29",
    "RR30",
    "RR31",
    "RR32",
    "RR33",
    "RR34",
    "RR35",
    "RR36",
    "RR37",
    "RR38",
    "RR39",
    "RR40",
    "RR41",
    "RR42",
    "RR43",
    "RR44",
    "RR45",
    "RR46",
    "RR47",
    "RR48",
    "RR49",
    "RR50",
    "RR51",
    "RR52",
    "RR53",
    "RR54",
    "RR55",
    "RR56",
    "RR57",
    "RR58",
    "RR59",
    "RR60",
    "RR61",
    "RR62",
    "RR63",
    "RR64",
    "RR65",
    "RR66",
    "RR67",
    "RR68",
    "RR69",
    "RR70",
    "RR71",
    "RR72",
    "RR73",
    "RR74",
    "RR75",
    "RR76",
    "RR77",
    "RR78",
    "RR79",
    "RR80",
    "RR81",
    "RR82",
    "RR83",
    "RR84",
    "RR85",
    "RR86",
    "RR87",
    "RR88",
    "RR89",
    "RR90",
    "RR91",
    "RR92",
    "RR93",
    "RR94",
    "RR95",
    "RR96",
    "RR97",
    "RR98",
    "RR99",
    "RR100",
    "RR101",
    "RR102",
    "RR103",
    "RR104",
    "RR105",
    "RR106",
    "RR107",
    "RR108",
    "RR109",
    "RR110",
    "RR111",
    "RR112",
    "RR113",
    "RR114",
    "RR115",
    "RR116",
    "RR117",
    "RR118",
    "RR119",
    "RR120",
    "RR121",
    "RR122",
    "RR123",
    "RR124",
    "RR125",
    "RR126",
    "RR127",
    "RR128",
    "RR129",
    "RR130",
    "RR131",
    "RR132",
    "RR133",
    "RR134",
    "RR135",
    "RR136",
    "RR137",
    "RR138",
    "RR139",
    "RR140",
    "RR141",
    "RR142",
    "RR143",
    "RR144",
    "RR145",
    "RR146",
    "RR147",
    "RR148",
    "RR149",
    "RR150",
    "RR151",
    "RR152",
    "RR153",
    "RR154",
    "RR155",
    "RR156",
    "RR157",
    "RR158",
    "RR159",
    "RR160",
    "RR161",
    "RR162",
    "RR163",
    "RR164",
    "RR165",
    "RR166",
    "RR167",
    "RR168",
    "RR169",
    "RR170",
    "RR171",
    "RR172",
    "RR173",
    "RR174",
    "RR175",
    "RR176",
    "RR177",
    "RR178",
    "RR179",
    "RR180",
    "RR181",
    "RR182",
    "RR183",
    "RR184",
    "RR185",
    "RR186",
    "RR187",
    "RR188",
    "RR189",
    "RR190",
    "RR191",
    "RR192",
    "RR193",
    "RR194",
    "RR195",
    "RR196",
    "RR197",
    "RR198",
    "RR199",
    "RR200",
    "RR201",
    "RR202",
    "RR203",
    "RR204",
    "RR205",
    "RR206",
    "RR207",
    "RR208",
    "RR209",
    "RR210",
    "RR211",
    "RR212",
    "RR213",
    "RR214",
    "RR215",
    "RR216",
    "RR217",
    "RR218",
    "RR219",
    "RR220",
    "RR221",
    "RR222",
    "RR223",
    "RR224",
    "RR225",
    "RR226",
    "RR227",
    "RR228",
    "RR229",
    "RR230",
    "RR231",
    "RR232",
    "RR233",
    "RR234",
    "RR235",
    "RR236",
    "RR237",
    "RR238",
    "RR239",
    "RR240",
    "RR241",
    "RR242",
    "RR243",
    "RR244",
    "RR245",
    "RR246",
    "RR247",
    "RR248",
    "RR249",
    "RR250",
    "RR251",
    "RR252",
    "RR253",
    "RR254",
    "RR255",
    "r0",
    "r1",
    "r2",
    "r3",
    "r4",
    "r5",
    "r6",
    "r7",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "rr0",
    "rr1",
    "rr2",
    "rr3",
    "rr4",
    "rr5",
    "rr6",
    "rr7",
    "rr8",
    "rr9",
    "rr10",
    "rr11",
    "rr12",
    "rr13",
    "rr14",
    "rr15",
    "RW",
    "RP",
    "cs", "ds"     // these 2 registers are required by the IDA kernel
};

static size_t numports = 0;
static ioport_t *ports = NULL;
static char device[MAXSTR] = "";

#include "../iocommon.cpp"

// returns a pointer to a ioport_t object if address was found in the config file.
// otherwise, returns NULL.
const ioport_t *find_sym(ea_t address) {
    return find_ioport(ports, numports, address);
}

static void patch_general_registers(const bool first_call = false) {
    char b[15];

    ushort style = (idpflags & CONF_GR_DEC ? 0 : idpflags & CONF_GR_HEX ? 1 : idpflags & CONF_GR_BIN ? 2 : 3);

    QASSERT(10079, style != 3);

    msg("General register print style: %s\n",
        style == 0 ? "decimal" : style == 1 ? "hexadecimal" : style == 2 ? "binary" : "unknown");

    for (int i = rR1; i < rR255; i++) {
        switch ( style ) {
            // decimal
            case 0:         qsnprintf(b, sizeof b, "R%d", i);
                            break;

            // hexadecimal
            case 1:         qsnprintf(b, sizeof b, "R0x%X", i);
                            break;

            // binary
            case 2:
                {
                    const int bits[] = { 128, 64, 32, 16, 8, 4, 2, 1 };
                    b[0] = 'R';
                    for (int k = 0; k < 8; k++) {
                        b[k + 1] = (i & bits[k]) ? '1' : '0';
                    }
                    b[9] = 'b';
                    b[10] = '\0';
                }
                break;
        }
        if ( !first_call )
            qfree((void *)RegNames[i]);

        RegNames[i] = qstrdup(b);
#if __DEBUG__
        msg("generated R%d => %s (%s)\n", i, b, RegNames[i]);
#endif /* __DEBUG__ */
    }
    dynamic_reg_names = true;
}

static void free_reg_names(void)
{
  if ( dynamic_reg_names )
  {
    for ( int i = rR1; i < rR255; i++)
    {
      qfree((void *)RegNames[i]);
      RegNames[i] = NULL;
    }
  }
}

static uint32 refresh_idpflags(void) {
    helper.create("$ st9");
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
            refresh_idpflags();
            {
              char buf[MAXSTR];
              if ( helper.supval(-1, buf, sizeof(buf)) > 0 )
                set_device_name(buf, IORESP_ALL);
            }
            break;

        case processor_t::term:
            free_reg_names();
        default:
            break;

        case processor_t::newfile:
            // default configuration
            idpflags = CONF_GR_DEC;
            // patch general registers names
            patch_general_registers(true);
            break;

       case processor_t::newseg:
            {
              segment_t *s = va_arg(va, segment_t *);
              // set RW/RP segment registers initial values
              s->defsr[rRW-ph.regFirstSreg] = 0;
              s->defsr[rRP-ph.regFirstSreg] = BADSEL;
            }
            break;

        case processor_t::oldfile:
            patch_general_registers();
            break;

        case processor_t::closebase:
        case processor_t::savebase:
            helper.altset(-1, idpflags);
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

    static ushort print_style = 3;

    static const char form[] =
        "HELP\n"
        "ST9 Related options :\n"
        "\n"
        " General registers print style\n"
        "\n"
        "       Select the format which will be used by IDA to\n"
        "       to print general registers.\n"
        "\n"
        "       For example,\n"
        "\n"
        "           R10                    (decimal) \n"
        "           R0x0A                (hexadecimal) \n"
        "           R00001010b      (binary) \n"
        "\n"
        "ENDHELP\n"
        "ST9 related options\n"
        "<##General registers print style##~D~ecimal (default):R>\n"
        "<~H~exadecimal:R>\n"
        "<~B~inary:R>>\n";

    if ( AskUsingForm_c(form, &print_style) ) {
        idpflags = 0;
        switch ( print_style ) {
            case 0:     idpflags |= CONF_GR_DEC; break;
            case 1:     idpflags |= CONF_GR_HEX; break;
            case 2:     idpflags |= CONF_GR_BIN; break;
        }
        if ( idpflags )
            patch_general_registers();
    }

    return IDPOPT_OK;
}

//
// GNU ST9+ Assembler description
//

// gets a function's name

static const char *gnu_get_func_name(func_t *pfn, char *buf, size_t bufsize)
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
static void idaapi gnu_func_header(func_t *pfn)
{
  std_gen_func_header(pfn);

  char buf[MAXSTR];
  const char *name = gnu_get_func_name(pfn, buf, sizeof(buf));
  if ( name != NULL )
  {
    printf_line(inf.indent, COLSTR(".desc %s, %s", SCOLOR_ASMDIR), name,
        pfn->is_far() ? "far" : "near");
    printf_line(inf.indent, COLSTR(".proc %s", SCOLOR_ASMDIR), name);
  }
  gl_xref = 1;
  printf_line(0, COLSTR("%s:", SCOLOR_ASMDIR), name);
}

// prints function footer
static void idaapi gnu_func_footer(func_t *pfn)
{
  char buf[MAXSTR];
  const char *name = gnu_get_func_name(pfn, buf, sizeof(buf));
  if ( name != NULL )
    printf_line(inf.indent, COLSTR(".endproc", SCOLOR_ASMDIR));
}

static asm_t gnu_asm = {
    AS_COLON |
    ASH_HEXF3 |   // hex 0x123 format
    ASB_BINF0 |   // bin 0110b format
    ASO_OCTF1 |   // oct 012345 format
    // don't display the final 0 in string declarations
    AS_ASCIIZ | AS_ASCIIC | AS_1TEXT,
    0,
    "ST9 GNU Assembler",
    0,
    NULL,         // no headers
    NULL,         // no bad instructions
    ".org",       // origin directive
    NULL,         // end directive
    ";",          // comment string
    '"',          // string delimiter
    '\'',         // char delimiter
    "\\\"'",      // special symbols in char and string constants

    ".ascii",     // ascii string directive
    ".byte",      // byte directive
    ".word",      // word directive
    ".long",      // dword  (4 bytes)
    NULL,         // qword  (8 bytes)
    NULL,         // oword  (16 bytes)

//  XXX
//
//  .float and .double directives are supposed to be supported by the
//  assembler, but when we try to assemble a file including those directives,
//  we get this error message :
//
//  /vob/st9plus/toolset/src/binutils/gas/config/tc-st9.c(4167): !!! STOP !!!
//  -> !(Floating point convertion)

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
    gnu_func_header,     // func_header
    gnu_func_footer,     // func_footer
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
    NULL,         // low16 op
    NULL          // high16 op
};

//
//  Alfred Arnold's Macro Assembler definition
//

static asm_t asw_asm = {
    AS_COLON |
    ASH_HEXF0 |        // hex 123h format
    ASB_BINF3 |        // bin 0b010 format
    ASO_OCTF5 |        // oct 123q format
    AS_1TEXT,          // 1 text per line, no bytes
    UAS_ASW,
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
    "DB",         // byte directive (alias: DB)
    "DW",         // word directive (alias: DW)
    "DD",         // dword  (4 bytes, alias: DD)
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

static asm_t *asms[] = { &gnu_asm, &asw_asm, NULL };

//
// Short and long name for our module
//

static const char *shnames[] = {
    "st9",
    NULL
};

static const char *lnames[] = {
    "ST9 Family",
    NULL
};

static uchar retcode_1[] = { 0x46 };    // ret
static uchar retcode_2[] = { 0xD3 };    // iret
static uchar retcode_3[] = { 0xF6, 01 };  // rets
static uchar retcode_4[] = { 0xEF, 31 };  // eret

static bytes_t retcodes[] = {
    { sizeof(retcode_1), retcode_1 },
    { sizeof(retcode_2), retcode_2 },
    { sizeof(retcode_3), retcode_3 },
    { sizeof(retcode_4), retcode_4 },
    { 0, NULL }                            // NULL terminated array
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
      IDP_INTERFACE_VERSION,// version
      PLFM_ST9,             // id
      PR_RNAMESOK           // can use register names for byte names
      |PR_BINMEM            // The module creates RAM/ROM segments for binary files
                            // (the kernel shouldn't ask the user about their sizes and addresses)
      |PR_SEGS              // has segment registers?
      |PR_SGROTHER,         // the segment registers don't contain
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

      rRW, rVds,
      0,                    // size of a segment register
      rVcs, rVds,

      NULL,                 // No known code start sequences
      retcodes,

      0, st9_last,
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
      NULL,                 // int (*get_frame_retsize(func_t *pfn)
      NULL,                 // void (*gen_stkvar_def)(char *buf,const member_t *mptr,int32 v);
      gen_spcdef,           // Generate text representation of an item in a special segment
      st9_ret,              // Icode of return instruction. It is ok to give any of possible return instructions
      set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
      NULL,                 // int (*is_align_insn)(ea_t ea);
      NULL                  // mvm_t *mvm;
};
