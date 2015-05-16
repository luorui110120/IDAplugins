/*
 *                      Interactive disassembler (IDA).
 *                      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                      ALL RIGHTS RESERVED.
 *                                                                                                                      E-mail: ig@estar.msk.su, ig@datarescue.com
 *                                                                                                                      FIDO:    2:5020/209
 *
 */

#include "arc.hpp"
#include <entry.hpp>
#include <srarea.hpp>

//--------------------------------------------------------------------------
processor_subtype_t ptype;
ea_t intmem = 0;
ea_t sfrmem = 0;

static const char *RegNames[] =
{
  "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",                       // 0 .. 7
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",                 // 8 .. 15
  "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",               // 16 .. 23
  "r24", "r25", "r26", "fp", "sp", "ilink1", "ilink2", "blink",         // 23 .. 31

  "r32", "r33", "r34", "r35", "r36", "r37", "r38", "r39",               // 31 .. 39
  "r40", "r41", "r42", "r43", "r44", "r45", "r46", "r47",               // 40 .. 47
  "r48", "r49", "r50", "r51", "r52", "r53", "r54", "r55",               // 48 .. 55
  "r56", "r57", "r58", "r59", "lp_count", "**61", "**62", "**63"        // 56 .. 63

  "rVcs", "rVds"
};

//----------------------------------------------------------------------
// The kernel event notifications
// Here you may take desired actions upon some kernel events

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
                        inf.mf = 0;                      // Set a big endian mode of the IDA kernel
                        break;

                case processor_t::newfile:
/*                      {
                                segment_t *sptr = get_first_seg();
                                segment_t *scode = get_first_seg();
                                set_segm_class(scode, "CODE");

                                // the default data segment will be INTMEM
                                set_default_dataseg(getseg(intmem)->sel);
                        } */
                        break;

                case processor_t::oldfile:
                        break;

                case processor_t::newseg:
                        break;

                case processor_t::newprc:
                        break;

                default:
                        break;
        }
        va_end(va);
        return(1);
}

static ushort gnu_bad_insn[]={ARC_flag, 0};

//-----------------------------------------------------------------------
//                                                                       ASMI
//-----------------------------------------------------------------------
static asm_t gnuas = {
        AS_COLON|AS_N2CHR|AS_1TEXT|ASH_HEXF3|ASO_OCTF1|ASB_BINF3|AS_ONEDUP|AS_ASCIIC,
        0,
        "GNU assembler",
        0,
        NULL,                                   // no headers
        gnu_bad_insn,   // GNU-as can't produce flag.f
        ".org",                         // org directive
        0,                                              // end directive
        "#",                                    // comment string
        '"',                                    // string delimiter
        '\'',                                   // char delimiter
        "\\\"'",                        // special symbols in char and string constants

        ".ascii",                       // ascii string directive
        ".byte",                        // byte directive
        ".short",                       // word directive
        ".long",                        // dword        (4 bytes)
        ".quad",                        // qword        (8 bytes)
        NULL,                                   // oword        (16 bytes)
        ".float",                       // float        (4 bytes)
        ".double",              // double (8 bytes)
        NULL,                                   // tbyte        (10/12 bytes)
        NULL,                                   // packed decimal real
        ".ds.#s(b,w,l,d) #d, #v", // arrays (#h,#d,#v,#s(...)
        ".space %s",    // uninited arrays
        "=",                                    // equ
        NULL,                                   // seg prefix
        NULL, NULL, NULL,
        NULL,                                   // xlat ascii
        ".",                                    // curent ip
        NULL,                                   // func_header
        NULL,                                   // func_footer
        ".global",              // public
        NULL,                                   // weak
        ".extern",              // extrn
        ".comm",                        // comm
        NULL,                                   // get_type_name
        ".align",                       // align
        '(', ')',                       // lbrace, rbrace
        "%",                                    // mod
        "&",                                    // and
        "|",                                    // or
        "^",                                    // xor
        "!",                                    // not
        "<<",                                   // shl
        ">>",                                   // shr
        NULL,                                   // sizeof
};


static asm_t *asms[] = { &gnuas, NULL };
//-----------------------------------------------------------------------
// The short and long names of the supported processors
// The short names must match
// the names in the module DESCRIPTION in the makefile (the
// description is copied in the offset 0x80 in the result DLL)

static const char *shnames[] =
{
        "ARC",
        NULL
};

static const char *lnames[] =
{
        "Argonaut RISC Core",
        NULL
};

//--------------------------------------------------------------------------
// Opcodes of "return" instructions. This information will be used in 2 ways:
//                      - if an instruction has the "return" opcode, its autogenerated label
//                              will be "locret" rather than "loc".
//                      - IDA will use the first "return" opcode to create empty subroutines.

static bytes_t retcodes[] = {
 { 0, NULL }                                                                                                            // NULL terminated array
};

#define PLFM_ARC        0x8000

//-----------------------------------------------------------------------
//                      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
        IDP_INTERFACE_VERSION,// version
        PLFM_ARC,                                                // id
        PR_RNAMESOK                                      // can use register names for byte names
        |PR_USE32|PR_DEFSEG32,
        8,                                                                              // 8 bits in a byte for code segments
        8,                                                                              // 8 bits in a byte for other segments

        shnames,                                                        // array of short processor names
                                                                                                // the short names are used to specify the processor
                                                                                                // with the -p command line switch)
        lnames,                                                         // array of long processor names
                                                                                                // the long names are used to build the processor type
                                                                                                // selection menu

        asms,                                                                   // array of target assemblers

        notify,                                                         // the kernel event notification callback

        header,                                                         // generate the disassembly header
        footer,                                                         // generate the disassembly footer

        segstart,                                                       // generate a segment declaration (start of segment)
        std_gen_segm_footer,    // generate a segment footer (end of segment)

        NULL,                                                                   // generate 'assume' directives

        ana,                                                                    // analyze an instruction and fill the 'cmd' structure
        emu,                                                                    // emulate an instruction

        out,                                                                    // generate a text representation of an instruction
        outop,                                                          // generate a text representation of an operand
        intel_data,                                             // generate a text representation of a data item
        NULL,                                                                   // compare operands
        NULL,                                                                   // can an operand have a type?

        qnumber(RegNames),              // Number of registers
        RegNames,                                                       // Register names
        NULL,                                                                   // get abstract register

        0,                                                                              // Number of register files
        NULL,                                                                   // Register file names
        NULL,                                                                   // Register descriptions
        NULL,                                                                   // Pointer to CPU registers

        64-1, 65-1,
        0,                                                                              // size of a segment register
        64-1, 65-1,

        NULL,                                                            // No known code start sequences
        retcodes,

        0, ARC_last,
        Instructions,
        NULL,
        NULL,
        0,              // size of tbyte
        NULL,
        { 0 },          // real width
        NULL,
        NULL,           // int32 (*gen_map_file)(FILE *fp);
        NULL,           // ea_t (*extract_address)(ea_t ea,const char *string,int x);
        is_sp_based,    // is the operand based on SP register?
        create_func_frame, // create frame of newly created function
        arc_get_frame_retsize, // get function return size
        NULL,              // generate declaration of stack variable
        gen_spcdef,        // generate text for an item in a special segment
};
