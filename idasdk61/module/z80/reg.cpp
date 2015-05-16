/*
 *      Interactive disassembler (IDA).
 *      Version 2.06
 *      Copyright (c) 1990-93 by Ilfak Guilfanov. (2:5020/209@fidonet)
 *      ALL RIGHTS RESERVED.
 *
 */

#include "i5.hpp"
#include <entry.hpp>
#include <diskio.hpp>

static const char *RegNames[] =
  {
    "b",  "c",  "d", "e", "h", "l", "m", "a",           // 0..7
    "bc", "de", "hl","psw","sp","ix","iy","af'",        // 8..15
    "r",  "i",  "f", "xl", "xh","yl","yh",              // 16..22

    "w",  "lw",  "ixl", "ixu", "dsr", "xsr", "iyl",
    "iyu", "ysr", "sr", "ib", "iw", "xm", "lck",
    "bc'", "de'", "hl'","ix'","iy'",
    "b'",  "c'",  "d'", "e'", "h'", "l'", "m'", "a'",

    "cs","ds"
  };

int pflag;

//-----------------------------------------------------------------------
//      PseudoSam assembler definiton
//-----------------------------------------------------------------------
static const char *ps_headers[] =
{
  ".code",
  NULL
};

static asm_t pseudosam = {
  AS_COLON | ASH_HEXF1 | AS_N2CHR,
  0,
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
  ".drw",       // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".rs %s",     // uninited arrays
  NULL,         // equ
  NULL,         // seg prefix
  NULL,         // checkarg_preline
  NULL,         // checkarg_atomprefix
  NULL,         // checkarg_operations
  NULL,         // XlatAsciiOutput
  NULL,         // curip
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      TASM assembler definiton for 8085
//-----------------------------------------------------------------------
static char tasmname[] = "Table Driven Assembler (TASM) by Speech Technology Inc.";
static asm_t tasm =
{
  AS_COLON | AS_N2CHR | AS_1TEXT,
  UAS_NPAIR | UAS_NOENS,
  tasmname,
  0,
  NULL,
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
  NULL,         // equ
  NULL,         // seg prefix
  NULL,         // checkarg_preline
  NULL,         // checkarg_atomprefix
  NULL,         // checkarg_operations
  NULL,         // XlatAsciiOutput
  NULL,         // curip
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      TASM assembler definiton for Z80
//-----------------------------------------------------------------------
static ushort tasmz80_bads[] = { I5_rst, Z80_srr, 0 };

static asm_t tasmz80 = {
  AS_COLON | AS_N2CHR | AS_1TEXT,
  UAS_NOENS | UAS_TOFF,
  "Table Driven Assembler (TASM) by Speech Technology Inc.",
  0,
  NULL,
  tasmz80_bads,
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
  NULL,         // equ
  NULL,         // seg prefix
  NULL,         // checkarg_preline
  NULL,         // checkarg_atomprefix
  NULL,         // checkarg_operations
  NULL,         // XlatAsciiOutput
  NULL,         // curip
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      Cross-16 assembler definiton (8085)
//-----------------------------------------------------------------------
static const char *cross16_headers[] = {
"cpu \"8085.tbl\"",
NULL };

static ushort cross_bads[] = { I5_cz, 0 };

static asm_t cross16 = {
  AS_COLON | AS_NHIAS,
  UAS_NPAIR,
  "Cross-16 by Universal Cross-Assemblers",
  0,
  cross16_headers,
  cross_bads,
  "org",
  "end",

  ";",          // comment string
  '"',          // string delimiter
  '\0',         // char delimiter (no char consts)
  "\\\"'",      // special symbols in char and string constants

  "dfb",        // ascii string directive
  "dfb",        // byte directive
  "dwl",        // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  "dfs %s",     // uninited arrays
  NULL,         // equ
  NULL,         // seg prefix
  NULL,         // checkarg_preline
  NULL,         // checkarg_atomprefix
  NULL,         // checkarg_operations
  NULL,         // XlatAsciiOutput
  NULL,         // curip
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      Cross-16 assembler definiton (z80)
//-----------------------------------------------------------------------
static const char *cross16z80_headers[] = {
"cpu \"z80.tbl\"",
NULL };

static const ushort cross16z80_bads[] = { Z80_set, Z80_srr, 0 };

static asm_t cross16z80 = {
  AS_COLON | AS_NHIAS,
  UAS_MKIMM,
  "Cross-16 by Universal Cross-Assemblers",
  0,
  cross16z80_headers,
  cross16z80_bads,
  "org",
  "end",

  ";",          // comment string
  '"',          // string delimiter
  '\0',         // char delimiter (no char consts)
  "\\\"'",      // special symbols in char and string constants

  "dfb",        // ascii string directive
  "dfb",        // byte directive
  "dwl",        // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  "dfs %s",     // uninited arrays
  NULL,         // equ
  NULL,         // seg prefix
  NULL,         // checkarg_preline
  NULL,         // checkarg_atomprefix
  NULL,         // checkarg_operations
  NULL,         // XlatAsciiOutput
  NULL,         // curip
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      A80 assembler definiton
//-----------------------------------------------------------------------
static const ushort a80_bads[] = { I5_rim, I5_sim, 0 };

static asm_t a80 = {
  AS_COLON | ASD_DECF1 | ASH_HEXF2 | AS_UNEQU,
  UAS_NPAIR,
  "A80 by ANTA electronics",
  0,
  NULL,
  a80_bads,
  "org",
  NULL,

  ";",          // comment string
  '\'',         // string delimiter
  '\0',         // char delimiter (no char consts)
  "'",          // special symbols in char and string constants

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
  NULL,         // uninited arrays
  "equ",
  NULL,         // seg prefix
  NULL,         // checkarg_preline
  NULL,         // checkarg_atomprefix
  NULL,         // checkarg_operations
  NULL,         // XlatAsciiOutput
  NULL,         // curip
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      A80 assembler definiton (Z80)
//-----------------------------------------------------------------------
static asm_t a80z = {
  AS_COLON | ASD_DECF1 | ASH_HEXF2 | AS_UNEQU,
  UAS_NPAIR | UAS_UNDOC | UAS_FUNNY,
  "A80 by ANTA electronics",
  0,
  NULL,
  a80_bads,
  "adr",
  NULL,

  ";",          // comment string
  '\'',         // string delimiter
  '\0',         // char delimiter (no char consts)
  "'",          // special symbols in char and string constants

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
  NULL,         // uninited arrays
  "equ",
  NULL,         // seg prefix
  NULL,         // checkarg_preline
  NULL,         // checkarg_atomprefix
  NULL,         // checkarg_operations
  NULL,         // XlatAsciiOutput
  NULL,         // curip
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      Avocet Macro Preprocessor v1.0 by Avocet Systems, Inc.
//-----------------------------------------------------------------------
static const char *avocet_headers[] = {
"; $chip(HD64180) ; please uncomment and place as first line for HD64180",
"       defseg allseg, absolute ; make avocet think that we have",
"       seg allseg              ; one big absolute segment",
NULL };

static const ushort avocet_bads[] = { Z80_srr, 0 };

static asm_t avocet = {
  AS_NHIAS,
  0,
  "Avocet Macro Preprocessor v1.0 by Avocet Systems, Inc.",
  0,
  avocet_headers,
  avocet_bads,
  "org",
  "end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\"'",        // special symbols in char and string constants

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
  NULL,         // equ
  NULL,         // seg prefix
  NULL,         // checkarg_preline
  NULL,         // checkarg_atomprefix
  NULL,         // checkarg_operations
  NULL,         // XlatAsciiOutput
  NULL,         // curip
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      ASxxxx by Alan R. Baldwin
//-----------------------------------------------------------------------
static const char *asxxxx_headers[] = {
"       .area   idaseg (ABS)",
"       .hd64 ; this is needed only for HD64180",
NULL };

static const ushort asxxxx_bads[] = { Z80_srr, I5_sub, 0 };

static asm_t asxxxx = {
  AS_NHIAS | AS_COLON | AS_NCHRE | AS_N2CHR | AS_1TEXT | ASH_HEXF3,
  UAS_MKIMM | UAS_MKOFF | UAS_CNDUP,
  "ASxxxx by Alan R. Baldwin v1.5",
  0,
  asxxxx_headers,
  asxxxx_bads,
  ".org",
  NULL,

  ";",          // comment string
  '\'',         // string delimiter
  '\'',         // char delimiter
  "'",          // special symbols in char and string constants

  ".ascii",     // ascii string directive
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
  ".ds %s",     // uninited arrays
  NULL,         // equ
  NULL,         // seg prefix
  NULL,         // checkarg_preline
  NULL,         // checkarg_atomprefix
  NULL,         // checkarg_operations
  NULL,         // XlatAsciiOutput
  NULL,         // curip
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      X-M-80 by Leo Sandy, (8080)
//-----------------------------------------------------------------------
static const char *xm80_headers[] = {
".8080",
NULL };

static const ushort xm80_bads[] = { I5_rim, I5_sim, Z80_srr, 0 };

static asm_t xm80 = {
  AS_COLON | AS_NHIAS,
  UAS_CSEGS,
  "X-M-80 by Leo Sandy",
  0,
  xm80_headers,
  xm80_bads,
  "org",
  "end",

  ";",          // comment string
  '\'',         // string delimiter
  '\'',         // char delimiter
  "'",          // special symbols in char and string constants

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
  NULL,         // equ
  NULL,         // seg prefix
  NULL,         // checkarg_preline
  NULL,         // checkarg_atomprefix
  NULL,         // checkarg_operations
  NULL,         // XlatAsciiOutput
  NULL,         // curip
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      X-M-80 by Leo Sandy, (Z80)
//-----------------------------------------------------------------------
static const char *xm80z_headers[] = {
".Z80",
NULL };

static asm_t xm80z = {
  AS_COLON | AS_NHIAS,
  UAS_CSEGS,
  "X-M-80 by Leo Sandy",
  0,
  xm80z_headers,
  xm80_bads,
  "org",
  "end",

  ";",          // comment string
  '\'',         // string delimiter
  '\'',         // char delimiter
  "'",          // special symbols in char and string constants

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
  NULL,         // equ
  NULL,         // seg prefix
  NULL,         // checkarg_preline
  NULL,         // checkarg_atomprefix
  NULL,         // checkarg_operations
  NULL,         // XlatAsciiOutput
  NULL,         // curip
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      Zilog Macro Assembler (ZMASM)
//-----------------------------------------------------------------------
static ushort zmasm_bads[] = { Z80_srr, 0 };

static asm_t zmasm =
{
  ASH_HEXF0 |       //   34h
  ASD_DECF0 |       //   34
  ASO_OCTF0 |       //   123o
  ASB_BINF0 |       //   010101b
  AS_N2CHR  |       // can't have 2 byte char consts
  AS_COLON  |       //   ':' after all labels
  AS_ASCIIC |       // ascii directive accepts C-like strings
  AS_ONEDUP |       // one dup directive per line
  0,
  UAS_ZMASM,
  "Zilog Macro Assembler",
  0,
  NULL,         // headers
  zmasm_bads,   // bads
  "org",
  "end",

  ";",          // comment string
  '\'',         // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

  ".ascii",     // ascii string directive
  "db",         // byte directive
  "dw",         // word directive
  "dl",         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  "#h [ #d ], #v", // arrays (#h,#d,#v,#s(...)
  "ds %s",      // uninited arrays
  "equ",        // equ
  NULL,         // seg prefix
  NULL,         // checkarg_preline
  NULL,         // checkarg_atomprefix
  NULL,         // checkarg_operations
  NULL,         // XlatAsciiOutput
  "$",          // curip
  NULL,         // func_header
  NULL,         // func_footer
  "public",     // public
  NULL,         // weak
  "extern",     // extrn
  NULL,         // comm
  NULL,         // get_type_name
  "align",      // align
  ' ', ' ',     // lbrace, rbrace
  "%",     // mod
  "&",     // and
  "|",     // or
  "^",     // xor
  "~",     // not
  "<<",    // shl
  ">>",    // shr
  NULL,    // sizeof
};

//-----------------------------------------------------------------------
//      RGBAsm v1.11 (part of ASMotor 1.10)
//-----------------------------------------------------------------------
static asm_t rgbasm =
{
  ASH_HEXF4 |       //   $34
  ASD_DECF0 |       //   34
  ASO_OCTF3 |       //   @123 (in fact this should be &123)
  ASB_BINF2 |       //   %010101
  AS_N2CHR  |       // can't have 2 byte char consts
  AS_COLON  |       //   ':' after all labels
  0,
  UAS_GBASM,
  "RGBAsm (part of ASMotor)",
  0,
  NULL,         // headers
  NULL,         // bads
  "org",
  NULL,         // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

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
  "equ",        // equ
  NULL,         // seg prefix
  NULL,         // checkarg_preline
  NULL,         // checkarg_atomprefix
  NULL,         // checkarg_operations
  NULL,         // XlatAsciiOutput
  "@",          // curip
  NULL,         // func_header
  NULL,         // func_footer
  "export",     // public
  NULL,         // weak
  "import",     // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  ' ', ' ',     // lbrace, rbrace
  "%",     // mod
  "&",     // and
  "|",     // or
  "^",     // xor
  "~",     // not
  "<<",    // shl
  ">>",    // shr
  NULL,    // sizeof
};

static asm_t *i8085asms[]   = { &tasm,    &xm80,   &pseudosam, &cross16, &a80, NULL };
static asm_t *Z80asms[]     = { &zmasm, &tasmz80, &xm80z,  &pseudosam, &cross16z80, &a80z, &avocet, &asxxxx, NULL };
static asm_t *HD64180asms[] = { &zmasm, &tasmz80, &avocet, &asxxxx, NULL };
static asm_t *GBasms[]      = { &rgbasm, NULL };
//----------------------------------------------------------------------
static netnode helper;
char device[MAXSTR] = "";
static size_t numports;
static ioport_t *ports;

#include "../iocommon.cpp"

//------------------------------------------------------------------
const char *z80_find_ioport(uval_t port)
{
  const ioport_t *p = find_ioport(ports, numports, port);
  return p ? p->name : NULL;
}

//------------------------------------------------------------------
const char *z80_find_ioport_bit(int port, int bit)
{
  const ioport_bit_t *p = find_ioport_bit(ports, numports, port, bit);
  return p ? p->name : NULL;
}

//------------------------------------------------------------------
const char *idaapi set_idp_options(const char *keyword,int /*value_type*/,const void * /*value*/)
{
  if ( keyword != NULL ) return IDPOPT_BADKEY;
  char cfgfile[QMAXFILE];
  get_cfg_filename(cfgfile, sizeof(cfgfile));
  if ( choose_ioport_device(cfgfile, device, sizeof(device), parse_area_line0) )
    set_device_name(device, IORESP_NONE);
  return IDPOPT_OK;
}

//----------------------------------------------------------------------
static char const features[] = { _PT_8085, _PT_Z80, _PT_64180, _PT_Z180, _PT_Z380, _PT_GB };

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
      helper.create("$ z80");
      break;

    case processor_t::newprc:
      {
        int np = va_arg(va, int);
        pflag = features[np];
        ph.assemblers = i8085asms;
        if ( isZ80() ) ph.assemblers = Z80asms;
        if ( is64180() ) ph.assemblers = HD64180asms;
        if ( isGB() ) ph.assemblers = GBasms;
        {
          char buf[MAXSTR];
          if ( helper.supval(-1, buf, sizeof(buf)) > 0 )
            set_device_name(buf, IORESP_NONE);
        }
      }
      break;

    case processor_t::newfile:
      if ( strcmp(inf.procName, "z180") == 0 )
      {
        char cfgfile[QMAXFILE];
        get_cfg_filename(cfgfile, sizeof(cfgfile));
        if ( choose_ioport_device(cfgfile, device, sizeof(device), parse_area_line0) )
          set_device_name(device, IORESP_AREA);
      }
      break;

    default:
      break;
  }
  va_end(va);

  return(1);
}

//-----------------------------------------------------------------------
static bool idaapi can_have_type(op_t &x)      // returns 1 - operand can have
{
  switch ( x.type )
  {
    case o_void:        // No Operand
    case o_reg:         // General Register
    case o_phrase:      // Base Reg + Index Reg
    case o_cond:        // FPP register
      return 0;
  }
  return 1;
}

//-----------------------------------------------------------------------
static const char *shnames[] = { "8085", "z80", "64180", "z180", "z380", "gb", NULL };
static const char *lnames[] = { "Intel 8085", "Zilog 80", "HD64180", "Zilog Z180", "Zilog Z380", "GameBoy", NULL };

//-----------------------------------------------------------------------
static uchar retcode_1[] = { 0xC9 };
static uchar retcode_2[] = { 0xED, 0x45 };
static uchar retcode_3[] = { 0xED, 0x4D };

static bytes_t retcodes[] =
{
 { sizeof(retcode_1), retcode_1 },
 { sizeof(retcode_2), retcode_2 },
 { sizeof(retcode_3), retcode_3 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      Intel 8080/8085 processor definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,
  PLFM_Z80,                     // id
  PRN_HEX|PR_SEGTRANS,
  8,                            // 8 bits in a byte for code segments
  8,                            // 8 bits in a byte for other segments


  shnames,
  lnames,

  i8085asms,

  notify,

  i5_header,
  i5_footer,

  i5_segstart,
  std_gen_segm_footer,

  NULL,                         // assumes

  i5_ana,
  i5_emu,

  i5_out,
  i5_outop,
  intel_data,
  NULL,                         // int  (*cmp_opnd)(op_t &op1,op_t &op2);
                                // returns 1 - equal operands
  can_have_type,                        // returns 1 - operand can have
                                        // a user-defined type

  R_vds+1,                              // number of registers
  RegNames,
  NULL,

  0,
  NULL,
  NULL,
  NULL,

//
//      There will be 2 virtual registers: code segment register
//                                         data segment register
//

  R_vcs,R_vds,                  // first, last
  0,                            // size of a segment register
  R_vcs,R_vds,                  // CS,DS

  NULL,                         // No known code start sequences
  retcodes,                     // 'Return' instruction codes

  0,I5_last,
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
  NULL,                 // long (*gen_map_file)(FILE *fp);
  NULL,                 // ea_t (*extract_address)(ea_t ea,const char *string,int x);
  NULL,                 // int (*is_sp_based)(op_t &x); -- always, so leave it NULL
  NULL,                 // int (*create_func_frame)(func_t *pfn);
  NULL,                 // int (*get_frame_retsize(func_t *pfn)
  NULL,                 // void (*gen_stkvar_def)(char *buf,const member_t *mptr,sval_t v);
  gen_spcdef,           // Generate text representation of an item in a special segment
  I5_ret,               // Icode of return instruction. It is ok to give any of possible return instructions
  set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
  NULL,                 // int (*is_align_insn)(ea_t ea);
  NULL,                 // mvm_t *mvm;
};
