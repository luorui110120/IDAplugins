/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *      Hitchi H8
 *
 */

#include "h8.hpp"

//--------------------------------------------------------------------------
struct map_t
{
  uchar proc;
  uchar itype;
  ushort op1;
  ushort op2;
};

#define MAP2         uchar(-1)
#define MAP3         uchar(-2)
#define MAP4         uchar(-3)
#define MAP014       uchar(-4)
#define LAST_MAP     MAP014

#ifdef __BORLANDC__
#if H8_last > LAST_MAP
#error "too many instruction types"
#endif
#endif


static const ushort OPTYPE = 0x1F;
static const ushort i3       =  1; // zero bit + immediate 3 bits in high nibble
static const ushort i8       =  2; // immediate 8 bits
static const ushort i16      =  3; // immediate 16 bits
static const ushort i32      =  4; // immediate 32 bits
static const ushort rCCR     =  5; // CCR
static const ushort rEXR     =  6; // EXR
static const ushort rLB      =  7; // register number in low nibble  (r0l..r7h)
static const ushort rHB      =  8; // register number in high nibble (r0l..r7h)
static const ushort rLW      =  9; // register number in low nibble  (r0..e7)
static const ushort rHW      = 10; // register number in high nibble (r0..e7)
static const ushort rLL0     = 11; // register number in low nibble
                                  // (er0..er7) high bit is zero
static const ushort rHL0     = 12; // register number in high nibble
                                  // (er0..er7) high bit is zero
static const ushort rLL1     = 13; // register number in low nibble
                                  // (er0..er7) high bit is one
static const ushort rHL1     = 14; // register number in high nibble
                                  // (er0..er7) high bit is one
static const ushort C1       = 15; // constant #1
static const ushort C2       = 16; // constant #2
static const ushort C4       = 17; // constant #4
static const ushort savedHL0 = 18; // same as rHL0 but uses code3
static const ushort savedAA  = 19; // absolute address in code3
static const ushort j8       = 20; // branch displacement 8 bit
static const ushort j16      = 21; // branch displacement 16 bit
static const ushort atHL     = 22; // @ERx
static const ushort aa8      = 23; // 8bit address
static const ushort aa16     = 24; // 16bit address
static const ushort aa24     = 25; // 24bit address
static const ushort aa32     = 26; // 32bit address
static const ushort rMACH    = 27; // MACH
static const ushort rMACL    = 28; // MACL
static const ushort d16      = 29; // @(d:16, ERs)
static const ushort ai8      = 30; // @@a8
static const ushort rV0      = 31; // 16bit or 32bit register depending
                                   // on the processor mode

static const ushort NEXT     = 0x20;  // read next byte

static const ushort CMD_SIZE = 0x1C0;  // .b
static const ushort B        = 0x040;  // .b
static const ushort W        = 0x080;  // .w
static const ushort L        = 0x0C0;  // .l
static const ushort V        = 0x100;  // .w or .l

static const ushort zL       = 0x0200; // low  nibble should be zero
static const ushort zH       = 0x0400; // high nibble should be zero
static const ushort MANUAL   = 0x0800; // manual processing
static const ushort X        = 0x1000; // no explicit postfix


//--------------------------------------------------------------------------
static map_t map[256] =
{
  { P300,       H8_nop,         NEXT|zL|zH,     0,               }, // 00
  { P300,       MAP2,           0,              0,               }, // 01
  { P300,       MAP2,           0,              0,               }, // 02
  { P300,       MAP2,           0,              0,               }, // 03
  { P300,       H8_orc,         i8,             rCCR,            }, // 04
  { P300,       H8_xorc,        i8,             rCCR,            }, // 05
  { P300,       H8_andc,        i8,             rCCR,            }, // 06
  { P300,       H8_ldc,         B | i8,         rCCR,            }, // 07
  { P300,       H8_add,         B | NEXT | rHB, rLB,             }, // 08
  { P300,       H8_add,         W | NEXT | rHW, rLW,             }, // 09
  { P300,       MAP2,           0,              0,               }, // 0A
  { P300,       MAP2,           0,              0,               }, // 0B
  { P300,       H8_mov,         B | NEXT | rHB, rLB,             }, // 0C
  { P300,       H8_mov,         W | NEXT | rHW, rLW,             }, // 0D
  { P300,       H8_addx,        NEXT | rHB,     rLB,             }, // 0E
  { P300,       MAP2,           0,              0,               }, // 0F

  { P300,       MAP2,           0,              0,               }, // 10
  { P300,       MAP2,           0,              0,               }, // 11
  { P300,       MAP2,           0,              0,               }, // 12
  { P300,       MAP2,           0,              0,               }, // 13
  { P300,       H8_or,          B | NEXT | rHB, rLB              }, // 14
  { P300,       H8_xor,         B | NEXT | rHB, rLB              }, // 15
  { P300,       H8_and,         B | NEXT | rHB, rLB              }, // 16
  { P300,       MAP2,           0,              0,               }, // 17
  { P300,       H8_sub,         B | NEXT | rHB, rLB              }, // 18
  { P300,       H8_sub,         W | NEXT | rHW, rLW,             }, // 19
  { P300,       MAP2,           0,              0,               }, // 1A
  { P300,       MAP2,           0,              0,               }, // 1B
  { P300,       H8_cmp,         B | NEXT | rHB, rLB              }, // 1C
  { P300,       H8_cmp,         W | NEXT | rHW, rLW,             }, // 1D
  { P300,       H8_subx,        NEXT | rHB,     rLB,             }, // 1E
  { P300,       MAP2,           0,              0,               }, // 1F

  { P300,       H8_mov,         B | aa8,        rLB,             }, // 20
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 21
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 22
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 23
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 24
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 25
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 26
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 27
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 28
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 29
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 2A
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 2B
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 2C
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 2D
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 2E
  { P300,       H8_mov,         B | aa8,        rLB,             }, // 2F

  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 30
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 31
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 32
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 33
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 34
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 35
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 36
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 37
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 38
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 39
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 3A
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 3B
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 3C
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 3D
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 3E
  { P300,       H8_mov,         B | rLB,        B | aa8,         }, // 3F

  { P300,       H8_bra,         j8,             0,               }, // 40
  { P300,       H8_brn,         j8,             0,               }, // 41
  { P300,       H8_bhi,         j8,             0,               }, // 42
  { P300,       H8_bls,         j8,             0,               }, // 43
  { P300,       H8_bcc,         j8,             0,               }, // 44
  { P300,       H8_bcs,         j8,             0,               }, // 45
  { P300,       H8_bne,         j8,             0,               }, // 46
  { P300,       H8_beq,         j8,             0,               }, // 47
  { P300,       H8_bvc,         j8,             0,               }, // 48
  { P300,       H8_bvs,         j8,             0,               }, // 49
  { P300,       H8_bpl,         j8,             0,               }, // 4A
  { P300,       H8_bmi,         j8,             0,               }, // 4B
  { P300,       H8_bge,         j8,             0,               }, // 4C
  { P300,       H8_blt,         j8,             0,               }, // 4D
  { P300,       H8_bgt,         j8,             0,               }, // 4E
  { P300,       H8_ble,         j8,             0,               }, // 4F

  { P300,       H8_mulxu,       B | NEXT | rHB, rLW,             }, // 50
  { P300,       H8_divxu,       B | NEXT | rHB, rLW,             }, // 51
  { P30A,       H8_mulxu,       W | NEXT | rHW, rLL0,            }, // 52
  { P30A,       H8_divxu,       W | NEXT | rHW, rLL0,            }, // 53
  { P300,       H8_rts,         0,              0,               }, // 54
  { P300,       H8_bsr,         j8,             0,               }, // 55
  { P300,       H8_rte,         0,              0,               }, // 56
  { P300,       H8_trapa,       MANUAL,         0,               }, // 57
  { P300,       MAP2,           0,              0,               }, // 58
  { P300,       H8_jmp,         NEXT | atHL,    0,               }, // 59
  { P300,       H8_jmp,         aa24,           0,               }, // 5A
  { P300,       H8_jmp,         ai8,            0,               }, // 5B
  { P300,       H8_bsr,         NEXT|zL|zH| j16,0,               }, // 5C
  { P300,       H8_jsr,         NEXT | atHL,    0,               }, // 5D
  { P300,       H8_jsr,         aa24,           0,               }, // 5E
  { P300,       H8_jsr,         ai8,            0,               }, // 5F

  { P300,       H8_bset,        NEXT | rHB,     rLB,             }, // 60
  { P300,       H8_bnot,        NEXT | rHB,     rLB,             }, // 61
  { P300,       H8_bclr,        NEXT | rHB,     rLB,             }, // 62
  { P300,       H8_btst,        NEXT | rHB,     rLB,             }, // 63
  { P300,       H8_or,          W | NEXT | rHW, rLW              }, // 64
  { P300,       H8_xor,         W | NEXT | rHW, rLW              }, // 65
  { P300,       H8_and,         W | NEXT | rHW, rLW              }, // 66
  { P300,       H8_bst,         NEXT | i3,      rLB,             }, // 67
  { P300,       H8_mov,         B | NEXT | atHL,rLB,             }, // 68
  { P300,       H8_mov,         W | NEXT | atHL,rLW,             }, // 69
  { P300,       MAP2,           0,              0,               }, // 6A
  { P300,       H8_mov,         MANUAL,         0,               }, // 6B
  { P300,       H8_mov,         MANUAL,         0,               }, // 6C
  { P300,       H8_mov,         MANUAL,         0,               }, // 6D
  { P300,       H8_mov,         B | NEXT | d16, rLB,             }, // 6E
  { P300,       H8_mov,         W | NEXT | d16, rLW,             }, // 6F

  { P300,       H8_bset,        NEXT | i3,      rLB,             }, // 70
  { P300,       H8_bnot,        NEXT | i3,      rLB,             }, // 71
  { P300,       H8_bclr,        NEXT | i3,      rLB,             }, // 72
  { P300,       H8_btst,        NEXT | i3,      rLB,             }, // 73
  { P300,       H8_bor,         NEXT | i3,      rLB,             }, // 74
  { P300,       H8_bxor,        NEXT | i3,      rLB,             }, // 75
  { P300,       H8_band,        NEXT | i3,      rLB,             }, // 76
  { P300,       H8_bld,         NEXT | i3,      rLB,             }, // 77
  { P300,       H8_mov,         MANUAL,         0,               }, // 78
  { P300,       MAP2,           0,              0,               }, // 79
  { P300,       MAP2,           0,              0,               }, // 7A
  { P300,       H8_eepmov,      0,              0,               }, // 7B
  { P300,       MAP3,           0,              0,               }, // 7C
  { P300,       MAP3,           0,              0,               }, // 7D
  { P300,       MAP3,           0,              0,               }, // 7E
  { P300,       MAP3,           0,              0,               }, // 7F

  { P300,       H8_add,         B | i8,         rLB,             }, // 80
  { P300,       H8_add,         B | i8,         rLB,             }, // 81
  { P300,       H8_add,         B | i8,         rLB,             }, // 82
  { P300,       H8_add,         B | i8,         rLB,             }, // 83
  { P300,       H8_add,         B | i8,         rLB,             }, // 84
  { P300,       H8_add,         B | i8,         rLB,             }, // 85
  { P300,       H8_add,         B | i8,         rLB,             }, // 86
  { P300,       H8_add,         B | i8,         rLB,             }, // 87
  { P300,       H8_add,         B | i8,         rLB,             }, // 88
  { P300,       H8_add,         B | i8,         rLB,             }, // 89
  { P300,       H8_add,         B | i8,         rLB,             }, // 8A
  { P300,       H8_add,         B | i8,         rLB,             }, // 8B
  { P300,       H8_add,         B | i8,         rLB,             }, // 8C
  { P300,       H8_add,         B | i8,         rLB,             }, // 8D
  { P300,       H8_add,         B | i8,         rLB,             }, // 8E
  { P300,       H8_add,         B | i8,         rLB,             }, // 8F

  { P300,       H8_addx,        i8,             rLB,             }, // 90
  { P300,       H8_addx,        i8,             rLB,             }, // 91
  { P300,       H8_addx,        i8,             rLB,             }, // 92
  { P300,       H8_addx,        i8,             rLB,             }, // 93
  { P300,       H8_addx,        i8,             rLB,             }, // 94
  { P300,       H8_addx,        i8,             rLB,             }, // 95
  { P300,       H8_addx,        i8,             rLB,             }, // 96
  { P300,       H8_addx,        i8,             rLB,             }, // 97
  { P300,       H8_addx,        i8,             rLB,             }, // 98
  { P300,       H8_addx,        i8,             rLB,             }, // 99
  { P300,       H8_addx,        i8,             rLB,             }, // 9A
  { P300,       H8_addx,        i8,             rLB,             }, // 9B
  { P300,       H8_addx,        i8,             rLB,             }, // 9C
  { P300,       H8_addx,        i8,             rLB,             }, // 9D
  { P300,       H8_addx,        i8,             rLB,             }, // 9E
  { P300,       H8_addx,        i8,             rLB,             }, // 9F

  { P300,       H8_cmp,         B | i8,         rLB,             }, // A0
  { P300,       H8_cmp,         B | i8,         rLB,             }, // A1
  { P300,       H8_cmp,         B | i8,         rLB,             }, // A2
  { P300,       H8_cmp,         B | i8,         rLB,             }, // A3
  { P300,       H8_cmp,         B | i8,         rLB,             }, // A4
  { P300,       H8_cmp,         B | i8,         rLB,             }, // A5
  { P300,       H8_cmp,         B | i8,         rLB,             }, // A6
  { P300,       H8_cmp,         B | i8,         rLB,             }, // A7
  { P300,       H8_cmp,         B | i8,         rLB,             }, // A8
  { P300,       H8_cmp,         B | i8,         rLB,             }, // A9
  { P300,       H8_cmp,         B | i8,         rLB,             }, // AA
  { P300,       H8_cmp,         B | i8,         rLB,             }, // AB
  { P300,       H8_cmp,         B | i8,         rLB,             }, // AC
  { P300,       H8_cmp,         B | i8,         rLB,             }, // AD
  { P300,       H8_cmp,         B | i8,         rLB,             }, // AE
  { P300,       H8_cmp,         B | i8,         rLB,             }, // AF

  { P300,       H8_subx,        i8,             rLB,             }, // B0
  { P300,       H8_subx,        i8,             rLB,             }, // B1
  { P300,       H8_subx,        i8,             rLB,             }, // B2
  { P300,       H8_subx,        i8,             rLB,             }, // B3
  { P300,       H8_subx,        i8,             rLB,             }, // B4
  { P300,       H8_subx,        i8,             rLB,             }, // B5
  { P300,       H8_subx,        i8,             rLB,             }, // B6
  { P300,       H8_subx,        i8,             rLB,             }, // B7
  { P300,       H8_subx,        i8,             rLB,             }, // B8
  { P300,       H8_subx,        i8,             rLB,             }, // B9
  { P300,       H8_subx,        i8,             rLB,             }, // BA
  { P300,       H8_subx,        i8,             rLB,             }, // BB
  { P300,       H8_subx,        i8,             rLB,             }, // BC
  { P300,       H8_subx,        i8,             rLB,             }, // BD
  { P300,       H8_subx,        i8,             rLB,             }, // BE
  { P300,       H8_subx,        i8,             rLB,             }, // BF

  { P300,       H8_or,          B | i8,         rLB,             }, // C0
  { P300,       H8_or,          B | i8,         rLB,             }, // C1
  { P300,       H8_or,          B | i8,         rLB,             }, // C2
  { P300,       H8_or,          B | i8,         rLB,             }, // C3
  { P300,       H8_or,          B | i8,         rLB,             }, // C4
  { P300,       H8_or,          B | i8,         rLB,             }, // C5
  { P300,       H8_or,          B | i8,         rLB,             }, // C6
  { P300,       H8_or,          B | i8,         rLB,             }, // C7
  { P300,       H8_or,          B | i8,         rLB,             }, // C8
  { P300,       H8_or,          B | i8,         rLB,             }, // C9
  { P300,       H8_or,          B | i8,         rLB,             }, // CA
  { P300,       H8_or,          B | i8,         rLB,             }, // CB
  { P300,       H8_or,          B | i8,         rLB,             }, // CC
  { P300,       H8_or,          B | i8,         rLB,             }, // CD
  { P300,       H8_or,          B | i8,         rLB,             }, // CE
  { P300,       H8_or,          B | i8,         rLB,             }, // CF

  { P300,       H8_xor,         B | i8,         rLB,             }, // D0
  { P300,       H8_xor,         B | i8,         rLB,             }, // D1
  { P300,       H8_xor,         B | i8,         rLB,             }, // D2
  { P300,       H8_xor,         B | i8,         rLB,             }, // D3
  { P300,       H8_xor,         B | i8,         rLB,             }, // D4
  { P300,       H8_xor,         B | i8,         rLB,             }, // D5
  { P300,       H8_xor,         B | i8,         rLB,             }, // D6
  { P300,       H8_xor,         B | i8,         rLB,             }, // D7
  { P300,       H8_xor,         B | i8,         rLB,             }, // D8
  { P300,       H8_xor,         B | i8,         rLB,             }, // D9
  { P300,       H8_xor,         B | i8,         rLB,             }, // DA
  { P300,       H8_xor,         B | i8,         rLB,             }, // DB
  { P300,       H8_xor,         B | i8,         rLB,             }, // DC
  { P300,       H8_xor,         B | i8,         rLB,             }, // DD
  { P300,       H8_xor,         B | i8,         rLB,             }, // DE
  { P300,       H8_xor,         B | i8,         rLB,             }, // DF

  { P300,       H8_and,         B | i8,         rLB,             }, // E0
  { P300,       H8_and,         B | i8,         rLB,             }, // E1
  { P300,       H8_and,         B | i8,         rLB,             }, // E2
  { P300,       H8_and,         B | i8,         rLB,             }, // E3
  { P300,       H8_and,         B | i8,         rLB,             }, // E4
  { P300,       H8_and,         B | i8,         rLB,             }, // E5
  { P300,       H8_and,         B | i8,         rLB,             }, // E6
  { P300,       H8_and,         B | i8,         rLB,             }, // E7
  { P300,       H8_and,         B | i8,         rLB,             }, // E8
  { P300,       H8_and,         B | i8,         rLB,             }, // E9
  { P300,       H8_and,         B | i8,         rLB,             }, // EA
  { P300,       H8_and,         B | i8,         rLB,             }, // EB
  { P300,       H8_and,         B | i8,         rLB,             }, // EC
  { P300,       H8_and,         B | i8,         rLB,             }, // ED
  { P300,       H8_and,         B | i8,         rLB,             }, // EE
  { P300,       H8_and,         B | i8,         rLB,             }, // EF

  { P300,       H8_mov,         B | rLB,        B | i8,          }, // F0
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // F1
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // F2
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // F3
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // F4
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // F5
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // F6
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // F7
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // F8
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // F9
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // FA
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // FB
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // FC
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // FD
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // FE
  { P300,       H8_mov,         B | rLB,        B | i8,          }, // FF

};


//--------------------------------------------------------------------------
static map_t map2_01[16] =
{
  { P300,       H8_mov,         MANUAL,         0,               }, // 01 0?
  { P300,       H8_ldm,         MANUAL,         0,               }, // 01 1?
  { P300,       H8_ldm,         MANUAL,         0,               }, // 01 2?
  { P300,       H8_ldm,         MANUAL,         0,               }, // 01 3?
  { P300,       MAP014,         0,              0,               }, // 01 4?
  { none,       H8_null,        0,              0,               }, // 01 5?
  { P2600,      H8_mac,         0,              0,               }, // 01 6?
  { none,       H8_null,        0,              0,               }, // 01 7?
  { P300,       H8_sleep,       zL,             0,               }, // 01 8?
  { none,       H8_null,        0,              0,               }, // 01 9?
  { P2600,      H8_clrmac,      zL,             0,               }, // 01 A?
  { none,       H8_null,        0,              0,               }, // 01 B?
  { P300,       MAP3,           0,              0,               }, // 01 C?
  { P300,       MAP3,           0,              0,               }, // 01 D?
  { P300,       H8_tas,         MANUAL,         0,               }, // 01 E?
  { P300,       MAP3,           0,              0,               }, // 01 F?
};

//--------------------------------------------------------------------------
static map_t map2_02[16] =
{
  { P300,       H8_stc,         B | rCCR,       rLB,             }, // 02 0?
  { P300,       H8_stc,         B | rEXR,       rLB,             }, // 02 1?
  { P2600,      H8_stmac,       rMACH,          rLL0,            }, // 02 2?
  { P2600,      H8_stmac,       rMACL,          rLL0,            }, // 02 3?
  { none,       H8_null,        0,              0,               }, // 02 4?
  { none,       H8_null,        0,              0,               }, // 02 5?
  { none,       H8_null,        0,              0,               }, // 02 6?
  { none,       H8_null,        0,              0,               }, // 02 7?
  { none,       H8_null,        0,              0,               }, // 02 8?
  { none,       H8_null,        0,              0,               }, // 02 9?
  { none,       H8_null,        0,              0,               }, // 02 A?
  { none,       H8_null,        0,              0,               }, // 02 B?
  { none,       H8_null,        0,              0,               }, // 02 C?
  { none,       H8_null,        0,              0,               }, // 02 D?
  { none,       H8_null,        0,              0,               }, // 02 E?
  { none,       H8_null,        0,              0,               }, // 02 F?
};

//--------------------------------------------------------------------------
static map_t map2_03[16] =
{
  { P300,       H8_ldc,         B | rLB,        rCCR,            }, // 03 0?
  { P300,       H8_ldc,         B | rLB,        rEXR,            }, // 03 1?
  { P2600,      H8_ldmac,       rLL0,           rMACH,           }, // 03 2?
  { P2600,      H8_ldmac,       rLL0,           rMACL,           }, // 03 3?
  { none,       H8_null,        0,              0,               }, // 03 4?
  { none,       H8_null,        0,              0,               }, // 03 5?
  { none,       H8_null,        0,              0,               }, // 03 6?
  { none,       H8_null,        0,              0,               }, // 03 7?
  { none,       H8_null,        0,              0,               }, // 03 8?
  { none,       H8_null,        0,              0,               }, // 03 9?
  { none,       H8_null,        0,              0,               }, // 03 A?
  { none,       H8_null,        0,              0,               }, // 03 B?
  { none,       H8_null,        0,              0,               }, // 03 C?
  { none,       H8_null,        0,              0,               }, // 03 D?
  { none,       H8_null,        0,              0,               }, // 03 E?
  { none,       H8_null,        0,              0,               }, // 03 F?
};

//--------------------------------------------------------------------------
static map_t map2_0A[16] =
{
  { P300,       H8_inc,         B | rLB,        0,               }, // 0A 0?
  { none,       H8_null,        0,              0,               }, // 0A 1?
  { none,       H8_null,        0,              0,               }, // 0A 2?
  { none,       H8_null,        0,              0,               }, // 0A 3?
  { none,       H8_null,        0,              0,               }, // 0A 4?
  { none,       H8_null,        0,              0,               }, // 0A 5?
  { none,       H8_null,        0,              0,               }, // 0A 6?
  { none,       H8_null,        0,              0,               }, // 0A 7?
  { P30A,       H8_add,         L | rHL1,       rLL0,            }, // 0A 8?
  { P30A,       H8_add,         L | rHL1,       rLL0,            }, // 0A 9?
  { P30A,       H8_add,         L | rHL1,       rLL0,            }, // 0A A?
  { P30A,       H8_add,         L | rHL1,       rLL0,            }, // 0A B?
  { P30A,       H8_add,         L | rHL1,       rLL0,            }, // 0A C?
  { P30A,       H8_add,         L | rHL1,       rLL0,            }, // 0A D?
  { P30A,       H8_add,         L | rHL1,       rLL0,            }, // 0A E?
  { P30A,       H8_add,         L | rHL1,       rLL0,            }, // 0A F?
};

//--------------------------------------------------------------------------
static map_t map2_0B[16] =
{
  { P300,       H8_adds,        C1,             rV0,             }, // 0B 0?
  { none,       H8_null,        0,              0,               }, // 0B 1?
  { none,       H8_null,        0,              0,               }, // 0B 2?
  { none,       H8_null,        0,              0,               }, // 0B 3?
  { none,       H8_null,        0,              0,               }, // 0B 4?
  { P300,       H8_inc,         W | C1,         rLW,             }, // 0B 5?
  { none,       H8_null,        0,              0,               }, // 0B 6?
  { P30A,       H8_inc,         L | C1,         rLL0,            }, // 0B 7?
  { P300,       H8_adds,        C2,             rV0,             }, // 0B 8?
  { P30A,       H8_adds,        C4,             rLL0,            }, // 0B 9?
  { none,       H8_null,        0,              0,               }, // 0B A?
  { none,       H8_null,        0,              0,               }, // 0B B?
  { none,       H8_null,        0,              0,               }, // 0B C?
  { P300,       H8_inc,         W | C2,         rLW,             }, // 0B D?
  { none,       H8_null,        0,              0,               }, // 0B E?
  { P30A,       H8_inc,         L | C2,         rLL0,            }, // 0B F?
};

//--------------------------------------------------------------------------
static map_t map2_0F[16] =
{
  { P300,       H8_daa,         rLB,            0,               }, // 0F 0?
  { none,       H8_null,        0,              0,               }, // 0F 1?
  { none,       H8_null,        0,              0,               }, // 0F 2?
  { none,       H8_null,        0,              0,               }, // 0F 3?
  { none,       H8_null,        0,              0,               }, // 0F 4?
  { none,       H8_null,        0,              0,               }, // 0F 5?
  { none,       H8_null,        0,              0,               }, // 0F 6?
  { none,       H8_null,        0,              0,               }, // 0F 7?
  { P30A,       H8_mov,         L | rLL0,       rHL1,            }, // 0F 8?
  { P30A,       H8_mov,         L | rLL0,       rHL1,            }, // 0F 9?
  { P30A,       H8_mov,         L | rLL0,       rHL1,            }, // 0F A?
  { P30A,       H8_mov,         L | rLL0,       rHL1,            }, // 0F B?
  { P30A,       H8_mov,         L | rLL0,       rHL1,            }, // 0F C?
  { P30A,       H8_mov,         L | rLL0,       rHL1,            }, // 0F D?
  { P30A,       H8_mov,         L | rLL0,       rHL1,            }, // 0F E?
  { P30A,       H8_mov,         L | rLL0,       rHL1,            }, // 0F F?
};

//--------------------------------------------------------------------------
static map_t map2_10[16] =
{
  { P300,       H8_shll,        B | rLB,        0,               }, // 10 0?
  { P300,       H8_shll,        W | rLW,        0,               }, // 10 1?
  { none,       H8_null,        0,              0,               }, // 10 2?
  { P30A,       H8_shll,        L | rLL0,       0,               }, // 10 3?
  { P300,       H8_shll,        B | C2,         rLB,             }, // 10 4?
  { P300,       H8_shll,        W | C2,         rLW,             }, // 10 5?
  { none,       H8_null,        0,              0,               }, // 10 6?
  { P30A,       H8_shll,        L | C2,         rLL0,            }, // 10 7?
  { P300,       H8_shal,        B | rLB,        0,               }, // 10 8?
  { P300,       H8_shal,        W | rLW,        0,               }, // 10 9?
  { none,       H8_null,        0,              0,               }, // 10 A?
  { P30A,       H8_shal,        L | rLL0,       0,               }, // 10 B?
  { P300,       H8_shal,        B | C2,         rLB,             }, // 10 C?
  { P300,       H8_shal,        W | C2,         rLW,             }, // 10 D?
  { none,       H8_null,        0,              0,               }, // 10 E?
  { P30A,       H8_shal,        L | C2,         rLL0,            }, // 10 F?
};

//--------------------------------------------------------------------------
static map_t map2_11[16] =
{
  { P300,       H8_shlr,        B | rLB,        0,               }, // 11 0?
  { P300,       H8_shlr,        W | rLW,        0,               }, // 11 1?
  { none,       H8_null,        0,              0,               }, // 11 2?
  { P30A,       H8_shlr,        L | rLL0,       0,               }, // 11 3?
  { P300,       H8_shlr,        B | C2,         rLB,             }, // 11 4?
  { P300,       H8_shlr,        W | C2,         rLW,             }, // 11 5?
  { none,       H8_null,        0,              0,               }, // 11 6?
  { P30A,       H8_shlr,        L | C2,         rLL0,            }, // 11 7?
  { P300,       H8_shar,        B | rLB,        0,               }, // 11 8?
  { P300,       H8_shar,        W | rLW,        0,               }, // 11 9?
  { none,       H8_null,        0,              0,               }, // 11 A?
  { P30A,       H8_shar,        L | rLL0,       0,               }, // 11 B?
  { P300,       H8_shar,        B | C2,         rLB,             }, // 11 C?
  { P300,       H8_shar,        W | C2,         rLW,             }, // 11 D?
  { none,       H8_null,        0,              0,               }, // 11 E?
  { P30A,       H8_shar,        L | C2,         rLL0,            }, // 11 F?
};

//--------------------------------------------------------------------------
static map_t map2_12[16] =
{
  { P300,       H8_rotxl,       B | rLB,        0,               }, // 12 0?
  { P300,       H8_rotxl,       W | rLW,        0,               }, // 12 1?
  { none,       H8_null,        0,              0,               }, // 12 2?
  { P30A,       H8_rotxl,       L | rLL0,       0,               }, // 12 3?
  { P300,       H8_rotxl,       B | C2,         rLB,             }, // 12 4?
  { P300,       H8_rotxl,       W | C2,         rLW,             }, // 12 5?
  { none,       H8_null,        0,              0,               }, // 12 6?
  { P30A,       H8_rotxl,       L | C2,         rLL0,            }, // 12 7?
  { P300,       H8_rotl,        B | rLB,        0,               }, // 12 8?
  { P300,       H8_rotl,        W | rLW,        0,               }, // 12 9?
  { none,       H8_null,        0,              0,               }, // 12 A?
  { P30A,       H8_rotl,        L | rLL0,       0,               }, // 12 B?
  { P300,       H8_rotl,        B | C2,         rLB,             }, // 12 C?
  { P300,       H8_rotl,        W | C2,         rLW,             }, // 12 D?
  { none,       H8_null,        0,              0,               }, // 12 E?
  { P30A,       H8_rotl,        L | C2,         rLL0,            }, // 12 F?
};

//--------------------------------------------------------------------------
static map_t map2_13[16] =
{
  { P300,       H8_rotxr,       B | rLB,        0,               }, // 13 0?
  { P300,       H8_rotxr,       W | rLW,        0,               }, // 13 1?
  { none,       H8_null,        0,              0,               }, // 13 2?
  { P30A,       H8_rotxr,       L | rLL0,       0,               }, // 13 3?
  { P300,       H8_rotxr,       B | C2,         rLB,             }, // 13 4?
  { P300,       H8_rotxr,       W | C2,         rLW,             }, // 13 5?
  { none,       H8_null,        0,              0,               }, // 13 6?
  { P30A,       H8_rotxr,       L | C2,         rLL0,            }, // 13 7?
  { P300,       H8_rotr,        B | rLB,        0,               }, // 13 8?
  { P300,       H8_rotr,        W | rLW,        0,               }, // 13 9?
  { none,       H8_null,        0,              0,               }, // 13 A?
  { P30A,       H8_rotr,        L | rLL0,       0,               }, // 13 B?
  { P300,       H8_rotr,        B | C2,         rLB,             }, // 13 C?
  { P300,       H8_rotr,        W | C2,         rLW,             }, // 13 D?
  { none,       H8_null,        0,              0,               }, // 13 E?
  { P30A,       H8_rotr,        L | C2,         rLL0,            }, // 13 F?
};

//--------------------------------------------------------------------------
static map_t map2_17[16] =
{
  { P300,       H8_not,         B | rLB,        0,               }, // 17 0?
  { P300,       H8_not,         W | rLW,        0,               }, // 17 1?
  { none,       H8_null,        0,              0,               }, // 17 2?
  { P30A,       H8_not,         L | rLL0,       0,               }, // 17 3?
  { none,       H8_null,        0,              0,               }, // 17 4?
  { P300,       H8_extu,        W | rLW,        0,               }, // 17 5?
  { none,       H8_null,        0,              0,               }, // 17 6?
  { P30A,       H8_extu,        L | rLL0,       0,               }, // 17 7?
  { P300,       H8_neg,         B | rLB,        0,               }, // 17 8?
  { P300,       H8_neg,         W | rLW,        0,               }, // 17 9?
  { none,       H8_null,        0,              0,               }, // 17 A?
  { P30A,       H8_neg,         L | rLL0,       0,               }, // 17 B?
  { none,       H8_null,        0,              0,               }, // 17 C?
  { P300,       H8_exts,        W | rLW,        0,               }, // 17 D?
  { none,       H8_null,        0,              0,               }, // 17 E?
  { P30A,       H8_exts,        L | rLL0,       0,               }, // 17 F?
};

//--------------------------------------------------------------------------
static map_t map2_1A[16] =
{
  { P300,       H8_dec,         B | rLB,        0,               }, // 1A 0?
  { none,       H8_null,        0,              0,               }, // 1A 1?
  { none,       H8_null,        0,              0,               }, // 1A 2?
  { none,       H8_null,        0,              0,               }, // 1A 3?
  { none,       H8_null,        0,              0,               }, // 1A 4?
  { none,       H8_null,        0,              0,               }, // 1A 5?
  { none,       H8_null,        0,              0,               }, // 1A 6?
  { none,       H8_null,        0,              0,               }, // 1A 7?
  { P30A,       H8_sub,         L | rHL1,       rLL0,            }, // 1A 8?
  { P30A,       H8_sub,         L | rHL1,       rLL0,            }, // 1A 9?
  { P30A,       H8_sub,         L | rHL1,       rLL0,            }, // 1A A?
  { P30A,       H8_sub,         L | rHL1,       rLL0,            }, // 1A B?
  { P30A,       H8_sub,         L | rHL1,       rLL0,            }, // 1A C?
  { P30A,       H8_sub,         L | rHL1,       rLL0,            }, // 1A D?
  { P30A,       H8_sub,         L | rHL1,       rLL0,            }, // 1A E?
  { P30A,       H8_sub,         L | rHL1,       rLL0,            }, // 1A F?
};

//--------------------------------------------------------------------------
static map_t map2_1B[16] =
{
  { P300,       H8_subs,        C1,             rV0,             }, // 1B 0?
  { none,       H8_null,        0,              0,               }, // 1B 1?
  { none,       H8_null,        0,              0,               }, // 1B 2?
  { none,       H8_null,        0,              0,               }, // 1B 3?
  { none,       H8_null,        0,              0,               }, // 1B 4?
  { P300,       H8_dec,         W | C1,         rLW,             }, // 1B 5?
  { none,       H8_null,        0,              0,               }, // 1B 6?
  { P30A,       H8_dec,         L | C1,         rLL0,            }, // 1B 7?
  { P300,       H8_subs,        C2,             rV0,             }, // 1B 8?
  { P30A,       H8_subs,        C4,             rLL0,            }, // 1B 9?
  { none,       H8_null,        0,              0,               }, // 1B A?
  { none,       H8_null,        0,              0,               }, // 1B B?
  { none,       H8_null,        0,              0,               }, // 1B C?
  { P300,       H8_dec,         W | C2,         rLW,             }, // 1B D?
  { none,       H8_null,        0,              0,               }, // 1B E?
  { P30A,       H8_dec,         L | C2,         rLL0,            }, // 1B F?
};

//--------------------------------------------------------------------------
static map_t map2_1F[16] =
{
  { P300,       H8_das,         rLB,            0,               }, // 1F 0?
  { none,       H8_null,        0,              0,               }, // 1F 1?
  { none,       H8_null,        0,              0,               }, // 1F 2?
  { none,       H8_null,        0,              0,               }, // 1F 3?
  { none,       H8_null,        0,              0,               }, // 1F 4?
  { none,       H8_null,        0,              0,               }, // 1F 5?
  { none,       H8_null,        0,              0,               }, // 1F 6?
  { none,       H8_null,        0,              0,               }, // 1F 7?
  { P30A,       H8_cmp,         L | rHL1,       rLL0,            }, // 1F 8?
  { P30A,       H8_cmp,         L | rHL1,       rLL0,            }, // 1F 9?
  { P30A,       H8_cmp,         L | rHL1,       rLL0,            }, // 1F A?
  { P30A,       H8_cmp,         L | rHL1,       rLL0,            }, // 1F B?
  { P30A,       H8_cmp,         L | rHL1,       rLL0,            }, // 1F C?
  { P30A,       H8_cmp,         L | rHL1,       rLL0,            }, // 1F D?
  { P30A,       H8_cmp,         L | rHL1,       rLL0,            }, // 1F E?
  { P30A,       H8_cmp,         L | rHL1,       rLL0,            }, // 1F F?
};

//--------------------------------------------------------------------------
static map_t map2_58[16] =
{
  { P300,       H8_bra,         zL | j16,       0,               }, // 58 0?
  { P300,       H8_brn,         zL | j16,       0,               }, // 58 1?
  { P300,       H8_bhi,         zL | j16,       0,               }, // 58 2?
  { P300,       H8_bls,         zL | j16,       0,               }, // 58 3?
  { P300,       H8_bcc,         zL | j16,       0,               }, // 58 4?
  { P300,       H8_bcs,         zL | j16,       0,               }, // 58 5?
  { P300,       H8_bne,         zL | j16,       0,               }, // 58 6?
  { P300,       H8_beq,         zL | j16,       0,               }, // 58 7?
  { P300,       H8_bvc,         zL | j16,       0,               }, // 58 8?
  { P300,       H8_bvs,         zL | j16,       0,               }, // 58 9?
  { P300,       H8_bpl,         zL | j16,       0,               }, // 58 A?
  { P300,       H8_bmi,         zL | j16,       0,               }, // 58 B?
  { P300,       H8_bge,         zL | j16,       0,               }, // 58 C?
  { P300,       H8_blt,         zL | j16,       0,               }, // 58 D?
  { P300,       H8_bgt,         zL | j16,       0,               }, // 58 E?
  { P300,       H8_ble,         zL | j16,       0,               }, // 58 F?
};

//--------------------------------------------------------------------------
static map_t map2_6A[16] =
{
  { P300,       H8_mov,         B | aa16,       rLB,             }, // 6A 0?
  { P300,       MAP4,           0,              0,               }, // 6A 1?
  { P300,       H8_mov,         B | aa32,       rLB,             }, // 6A 2?
  { P300,       MAP4,           0,              0,               }, // 6A 3?
  { P300,       H8_movfpe,      B | X | aa16,   rLB,             }, // 6A 4?
  { none,       H8_null,        0,              0,               }, // 6A 5?
  { none,       H8_null,        0,              0,               }, // 6A 6?
  { none,       H8_null,        0,              0,               }, // 6A 7?
  { P300,       H8_mov,         B | aa16,       rLB,             }, // 6A 8?
  { none,       H8_null,        0,              0,               }, // 6A 9?
  { P300,       H8_mov,         B | aa32,       rLB,             }, // 6A A?
  { none,       H8_null,        0,              0,               }, // 6A B?
  { P300,       H8_movtpe,      rLB,            B | aa16,        }, // 6A C?
  { none,       H8_null,        0,              0,               }, // 6A D?
  { none,       H8_null,        0,              0,               }, // 6A E?
  { none,       H8_null,        0,              0,               }, // 6A F?
};

//--------------------------------------------------------------------------
static map_t map2_79[16] =
{
  { P300,       H8_mov,         W | i16,        rLW              }, // 79 0?
  { P300,       H8_add,         W | i16,        rLW              }, // 79 1?
  { P300,       H8_cmp,         W | i16,        rLW              }, // 79 2?
  { P300,       H8_sub,         W | i16,        rLW              }, // 79 3?
  { P300,       H8_or,          W | i16,        rLW              }, // 79 4?
  { P300,       H8_xor,         W | i16,        rLW              }, // 79 5?
  { P300,       H8_and,         W | i16,        rLW              }, // 79 6?
  { none,       H8_null,        0,              0,               }, // 79 7?
  { none,       H8_null,        0,              0,               }, // 79 8?
  { none,       H8_null,        0,              0,               }, // 79 9?
  { none,       H8_null,        0,              0,               }, // 79 A?
  { none,       H8_null,        0,              0,               }, // 79 B?
  { none,       H8_null,        0,              0,               }, // 79 C?
  { none,       H8_null,        0,              0,               }, // 79 D?
  { none,       H8_null,        0,              0,               }, // 79 E?
  { none,       H8_null,        0,              0,               }, // 79 F?
};

//--------------------------------------------------------------------------
static map_t map2_7A[16] =
{
  { P30A,       H8_mov,         L | i32,        rLL0,            }, // 7A 0?
  { P30A,       H8_add,         L | i32,        rLL0,            }, // 7A 1?
  { P30A,       H8_cmp,         L | i32,        rLL0,            }, // 7A 2?
  { P30A,       H8_sub,         L | i32,        rLL0,            }, // 7A 3?
  { P30A,       H8_or,          L | i32,        rLL0,            }, // 7A 4?
  { P30A,       H8_xor,         L | i32,        rLL0,            }, // 7A 5?
  { P30A,       H8_and,         L | i32,        rLL0,            }, // 7A 6?
  { none,       H8_null,        0,              0,               }, // 7A 7?
  { none,       H8_null,        0,              0,               }, // 7A 8?
  { none,       H8_null,        0,              0,               }, // 7A 9?
  { none,       H8_null,        0,              0,               }, // 7A A?
  { none,       H8_null,        0,              0,               }, // 7A B?
  { none,       H8_null,        0,              0,               }, // 7A C?
  { none,       H8_null,        0,              0,               }, // 7A D?
  { none,       H8_null,        0,              0,               }, // 7A E?
  { none,       H8_null,        0,              0,               }, // 7A F?
};

//--------------------------------------------------------------------------
static map_t map3_01C05[8] =
{
  { P300,       H8_mulxs,       B | NEXT | rHB, rLW,             }, // 01 C0 50
  { none,       H8_null,        0,              0,               }, // 01 C0 51
  { P30A,       H8_mulxs,       W | NEXT | rHW, rLL0,            }, // 01 C0 52
  { none,       H8_null,        0,              0,               }, // 01 C0 53
  { none,       H8_null,        0,              0,               }, // 01 C0 54
  { none,       H8_null,        0,              0,               }, // 01 C0 55
  { none,       H8_null,        0,              0,               }, // 01 C0 56
  { none,       H8_null,        0,              0,               }, // 01 C0 57
};

//--------------------------------------------------------------------------
static map_t map3_01D05[8] =
{
  { none,       H8_null,        0,              0,               }, // 01 D0 50
  { P300,       H8_divxs,       B | NEXT | rHB, rLW,             }, // 01 D0 51
  { none,       H8_null,        0,              0,               }, // 01 D0 52
  { P30A,       H8_divxs,       W | NEXT | rHW, rLL0,            }, // 01 D0 53
  { none,       H8_null,        0,              0,               }, // 01 D0 54
  { none,       H8_null,        0,              0,               }, // 01 D0 55
  { none,       H8_null,        0,              0,               }, // 01 D0 56
  { none,       H8_null,        0,              0,               }, // 01 D0 57
};

//--------------------------------------------------------------------------
static map_t map3_01F06[8] =
{
  { none,       H8_null,        0,              0,               }, // 01 F0 60
  { none,       H8_null,        0,              0,               }, // 01 F0 61
  { none,       H8_null,        0,              0,               }, // 01 F0 62
  { none,       H8_null,        0,              0,               }, // 01 F0 63
  { P30A,       H8_or,          L | NEXT | rHL0,rLL0,            }, // 01 F0 64
  { P30A,       H8_xor,         L | NEXT | rHL0,rLL0,            }, // 01 F0 65
  { P30A,       H8_and,         L | NEXT | rHL0,rLL0,            }, // 01 F0 66
  { none,       H8_null,        0,              0,               }, // 01 F0 67
};

//--------------------------------------------------------------------------
static map_t map3_7Cr06[8] =
{
  { none,       H8_null,        0,              0,               }, // 7C r0 60
  { none,       H8_null,        0,              0,               }, // 7C r0 61
  { none,       H8_null,        0,              0,               }, // 7C r0 62
  { P300,       H8_btst,        NEXT | rHB | zL,savedHL0,        }, // 7C r0 63
  { none,       H8_null,        0,              0,               }, // 7C r0 64
  { none,       H8_null,        0,              0,               }, // 7C r0 65
  { none,       H8_null,        0,              0,               }, // 7C r0 66
  { none,       H8_null,        0,              0,               }, // 7C r0 67
};

//--------------------------------------------------------------------------
static map_t map3_7Cr07[8] =
{
  { none,       H8_null,        0,              0,               }, // 7C r0 70
  { none,       H8_null,        0,              0,               }, // 7C r0 71
  { none,       H8_null,        0,              0,               }, // 7C r0 72
  { P300,       H8_btst,        NEXT | i3 | zL, savedHL0,        }, // 7C r0 73
  { P300,       H8_bor,         NEXT | i3 | zL, savedHL0,        }, // 7C r0 74
  { P300,       H8_bxor,        NEXT | i3 | zL, savedHL0,        }, // 7C r0 75
  { P300,       H8_band,        NEXT | i3 | zL, savedHL0,        }, // 7C r0 76
  { P300,       H8_bld,         NEXT | i3 | zL, savedHL0,        }, // 7C r0 77
};

//--------------------------------------------------------------------------
static map_t map3_7Dr06[8] =
{
  { P300,       H8_bset,        NEXT | rHB | zL,savedHL0,        }, // 7D r0 60
  { P300,       H8_bnot,        NEXT | rHB | zL,savedHL0,        }, // 7D r0 61
  { P300,       H8_bclr,        NEXT | rHB | zL,savedHL0,        }, // 7D r0 62
  { none,       H8_null,        0,              0,               }, // 7D r0 63
  { none,       H8_null,        0,              0,               }, // 7D r0 64
  { none,       H8_null,        0,              0,               }, // 7D r0 65
  { none,       H8_null,        0,              0,               }, // 7D r0 66
  { P300,       H8_bst,         NEXT | i3  | zL,savedHL0,        }, // 7D r0 67
};

//--------------------------------------------------------------------------
static map_t map3_7Dr07[8] =
{
  { P300,       H8_bset,        NEXT | i3 | zL, savedHL0,        }, // 7D r0 70
  { P300,       H8_bnot,        NEXT | i3 | zL, savedHL0,        }, // 7D r0 71
  { P300,       H8_bclr,        NEXT | i3 | zL, savedHL0,        }, // 7D r0 72
  { none,       H8_null,        0,              0,               }, // 7D r0 73
  { none,       H8_null,        0,              0,               }, // 7D r0 74
  { none,       H8_null,        0,              0,               }, // 7D r0 75
  { none,       H8_null,        0,              0,               }, // 7D r0 76
  { none,       H8_null,        0,              0,               }, // 7D r0 77
};

//--------------------------------------------------------------------------
static map_t map3_7Eaa6[8] =
{
  { none,       H8_null,        0,              0,               }, // 7E aa 60
  { none,       H8_null,        0,              0,               }, // 7E aa 61
  { none,       H8_null,        0,              0,               }, // 7E aa 62
  { P300,       H8_btst,        NEXT | rHB | zL,savedAA,         }, // 7E r0 63
  { none,       H8_null,        0,              0,               }, // 7E aa 64
  { none,       H8_null,        0,              0,               }, // 7E aa 65
  { none,       H8_null,        0,              0,               }, // 7E aa 66
  { none,       H8_null,        0,              0,               }, // 7E aa 67
};

//--------------------------------------------------------------------------
static map_t map3_7Eaa7[8] =
{
  { none,       H8_null,        0,              0,               }, // 7E aa 70
  { none,       H8_null,        0,              0,               }, // 7E aa 71
  { none,       H8_null,        0,              0,               }, // 7E aa 72
  { P300,       H8_btst,        NEXT | i3 | zL, savedAA,         }, // 7E aa 73
  { P300,       H8_bor,         NEXT | i3 | zL, savedAA,         }, // 7E aa 74
  { P300,       H8_bxor,        NEXT | i3 | zL, savedAA,         }, // 7E aa 75
  { P300,       H8_band,        NEXT | i3 | zL, savedAA,         }, // 7E aa 76
  { P300,       H8_bld,         NEXT | i3 | zL, savedAA,         }, // 7E aa 77
};

//--------------------------------------------------------------------------
static map_t map3_7Faa6[8] =
{
  { P300,       H8_bset,        NEXT | rHB | zL,savedAA,         }, // 7F aa 60
  { P300,       H8_bnot,        NEXT | rHB | zL,savedAA,         }, // 7F aa 61
  { P300,       H8_bclr,        NEXT | rHB | zL,savedAA,         }, // 7F aa 62
  { none,       H8_null,        0,              0,               }, // 7F aa 63
  { none,       H8_null,        0,              0,               }, // 7F aa 64
  { none,       H8_null,        0,              0,               }, // 7F aa 65
  { none,       H8_null,        0,              0,               }, // 7F aa 66
  { P300,       H8_bst,         NEXT | i3  | zL,savedAA,         }, // 7F aa 67
};

//--------------------------------------------------------------------------
static map_t map3_7Faa7[8] =
{
  { P300,       H8_bset,        NEXT | i3 | zL, savedAA,         }, // 7F r0 70
  { P300,       H8_bnot,        NEXT | i3 | zL, savedAA,         }, // 7F r0 71
  { P300,       H8_bclr,        NEXT | i3 | zL, savedAA,         }, // 7F r0 72
  { none,       H8_null,        0,              0,               }, // 7F aa 73
  { none,       H8_null,        0,              0,               }, // 7F aa 74
  { none,       H8_null,        0,              0,               }, // 7F aa 75
  { none,       H8_null,        0,              0,               }, // 7F aa 76
  { none,       H8_null,        0,              0,               }, // 7F aa 77
};

//--------------------------------------------------------------------------
struct map2_pointer_t
{
  uchar prefix;
  map_t *map;
};

static map2_pointer_t map2[] =
{
  { 0x01, map2_01 },
  { 0x02, map2_02 },
  { 0x03, map2_03 },
  { 0x0A, map2_0A },
  { 0x0B, map2_0B },
  { 0x0F, map2_0F },
  { 0x10, map2_10 },
  { 0x11, map2_11 },
  { 0x12, map2_12 },
  { 0x13, map2_13 },
  { 0x17, map2_17 },
  { 0x1A, map2_1A },
  { 0x1B, map2_1B },
  { 0x1F, map2_1F },
  { 0x58, map2_58 },
  { 0x6A, map2_6A },
  { 0x79, map2_79 },
  { 0x7A, map2_7A },
};

struct map3_pointer_t
{
  uint32 prefix;
  uint32 mask;           // bit set means that the bit is ignored
  map_t *map;
};

static map3_pointer_t map3[] =
{
  { 0x01C05, 0x000, map3_01C05 },
  { 0x01D05, 0x000, map3_01D05 },
  { 0x01F06, 0x000, map3_01F06 },
  { 0x7C006, 0xF00, map3_7Cr06 },
  { 0x7C007, 0xF00, map3_7Cr07 },
  { 0x7D006, 0xF00, map3_7Dr06 },
  { 0x7D007, 0xF00, map3_7Dr07 },
  { 0x7E006, 0xFF0, map3_7Eaa6 },
  { 0x7E007, 0xFF0, map3_7Eaa7 },
  { 0x7F006, 0xFF0, map3_7Faa6 },
  { 0x7F007, 0xFF0, map3_7Faa7 },
};

static uchar code;
static uchar code3;

//--------------------------------------------------------------------------
void interr(const char *module)
{
  const char *name = NULL;
  if ( cmd.itype < H8_last )
    name = Instructions[cmd.itype].name;
  else
    cmd.itype = H8_null;
  warning("%a(%s): internal error in %s", cmd.ea, name, module);
}

//--------------------------------------------------------------------------
static void trimaddr(op_t &x)
{
  if ( cmd.auxpref & aux_disp32 ) return;
  x.addr &= 0xFFFFFFL;
  if ( cmd.auxpref & aux_disp24 )
  {
    ;
  }
  else if ( cmd.auxpref & aux_disp16 )
  {
    x.addr &= 0x00FFFFL;
    if ( x.type == o_mem && advanced() && (x.addr & 0x8000) != 0 )
      x.addr |= 0xFF0000;
  }
  else
  {
    if ( !advanced() )
      x.addr &= 0x00FFFFL;
  }
}

//--------------------------------------------------------------------------
static void get_disp(op_t &x, bool disp32)
{
  x.offb = (uchar)cmd.size;
  if ( !disp32 )
  {
    cmd.auxpref |= aux_disp16;
    x.addr = short(ua_next_word());
  }
  else
  {
    cmd.auxpref |= aux_disp32;
    x.addr = ua_next_long();
  }
}

//--------------------------------------------------------------------------
static void opimm8(op_t &x)
{
  x.offb = (uchar)cmd.size;
  x.type = o_imm;
  x.dtyp = dt_byte;
  x.value = ua_next_byte();
}

//--------------------------------------------------------------------------
static void opreg8(op_t &x, uint16 reg)
{
  x.type = o_reg;
  x.dtyp = dt_byte;
  x.reg  = reg;
}

//--------------------------------------------------------------------------
inline regnum_t r0(void) { return advanced() ? ER0 : R0; }

//--------------------------------------------------------------------------
static void opatHL(op_t &x, char dtyp)
{
  x.type = o_phrase;
  x.dtyp = dtyp;
  x.reg  = r0() + ((code>>4) & 7);
  x.phtype = ph_normal;
}

//--------------------------------------------------------------------------
static void oppost(op_t &x, uint16 reg, char dtyp)
{
  x.type   = o_phrase;
  x.dtyp   = dtyp;
  x.reg    = reg;
  x.phtype = ph_post;
}

//--------------------------------------------------------------------------
static void opdsp16(op_t &x, char dtyp)
{
  x.type = o_displ;
  x.dtyp = dtyp;
  x.reg  = r0() + ((code>>4) & 7);
  get_disp(x, false);
  if ( isOff(get_flags_novalue(cmd.ea), -1) )
    x.addr = ushort(x.addr);
}

//--------------------------------------------------------------------------
static void opdsp32(op_t &x, char dtyp)
{
  x.type = o_displ;
  x.dtyp = dtyp;
  x.reg  = r0() + ((code>>4) & 7);
  get_disp(x, true);
}

//--------------------------------------------------------------------------
static void opreg(op_t &x, uint16 reg, char dtyp)
{
  switch ( dtyp )
  {
    case dt_byte:
      reg += R0H;
      break;
    case dt_word:
      reg += R0;
      break;
    case dt_dword:
      reg += ER0;
      break;
  }
  x.type = o_reg;
  x.dtyp = dtyp;
  x.reg  = reg;
}

//--------------------------------------------------------------------------
static char calc_dtyp(ushort flags)
{
  char dtyp;
       if ( flags & B ) dtyp = dt_byte;
  else if ( flags & W ) dtyp = dt_word;
  else if ( flags & L ) dtyp = dt_dword;
  else                  dtyp = dt_code;
  return dtyp;
}

//--------------------------------------------------------------------------
static bool read_operand(op_t &x, ushort flags)
{
  if ( flags & NEXT ) code = ua_next_byte();
  if ( (flags & zL) && (code & 0x0F) != 0 ) return false;
  if ( (flags & zH) && (code & 0xF0) != 0 ) return false;

  switch ( flags & OPTYPE )
  {
    case 0:       // none
      break;
    case i3:      // immediate 3 bits
      x.type = o_imm;
      x.dtyp = dt_byte;
      x.value = (code >> 4) & 7;
      break;
    case i8  :    // immediate 8 bits
      opimm8(x);
      break;
    case i16:     // immediate 16 bits
      x.offb = (uchar)cmd.size;
      x.type = o_imm;
      x.dtyp = dt_word;
      x.value = ua_next_word();
      break;
    case i32:     // immediate 32 bits
      if ( !advanced() ) return false;
      x.offb = (uchar)cmd.size;
      x.type = o_imm;
      x.dtyp = dt_dword;
      x.value = ua_next_long();
      break;
    case rCCR:    // CCR
      opreg8(x, CCR);
      break;
    case rEXR:    // EXR
      opreg8(x, EXR);
      break;
    case rLB:     // register number in low nibble  (r0l..r7h)
      opreg8(x, R0H + (code & 15));
      break;
    case rHB:     // register number in high nibble (r0l..r7h)
      opreg8(x, R0H + ((code>>4) & 15));
      break;
    case rLW:     // register number in low nibble  (r0..e7)
LW:
      x.type = o_reg;
      x.dtyp = dt_word;
      x.reg  = R0 + (code & 15);
      break;
    case rHW:     // register number in high nibble (r0..e7)
      x.type = o_reg;
      x.dtyp = dt_word;
      x.reg  = R0 + ((code>>4) & 15);
      break;
    case rV0:     // register number in low nibble
      if ( (code & 0x08) != 0 ) return false;
      if ( !advanced() ) goto LW;
      goto LL;
    case rLL0:    // register number in low nibble
      if ( (code & 0x08) != 0 ) return false;
      if ( !advanced() ) return false;
LL:
      x.type = o_reg;
      x.dtyp = dt_dword;
      x.reg  = ER0 + (code & 7);
      break;
    case rHL0:    // register number in high nibble
      if ( (code & 0x80) != 0 ) return false;
      if ( !advanced() ) return false;
HL:
      x.type = o_reg;
      x.dtyp = dt_dword;
      x.reg  = ER0 + ((code>>4) & 7);
      break;
    case rMACH:
      x.type = o_reg;
      x.dtyp = dt_dword;
      x.reg  = MACH;
      break;
    case rMACL:
      x.type = o_reg;
      x.dtyp = dt_dword;
      x.reg  = MACL;
      break;
    case savedHL0:      // @ERx
      if ( (code3 & 0x80) != 0 ) return false;
      x.type = o_phrase;
      x.dtyp = dt_dword;
      x.reg  = r0() + ((code3>>4) & 7);
      x.phtype = ph_normal;
      break;
    case atHL:          // @ERx
      opatHL(x, calc_dtyp(flags));
      break;
    case rLL1:    // register number in low nibble
      if ( (code & 0x08) == 0 ) return false;
      if ( !advanced() ) return false;
      goto LL;
    case rHL1:    // register number in high nibble
      if ( (code & 0x80) == 0 ) return false;
      if ( !advanced() ) return false;
      goto HL;
    case C1:      // constant #1
      x.type = o_imm;
      x.dtyp = dt_byte;
      x.value = 1;
      break;
    case C2:      // constant #2
      x.type = o_imm;
      x.dtyp = dt_byte;
      x.value = 2;
      break;
    case C4:      // constant #4
      x.type = o_imm;
      x.dtyp = dt_byte;
      x.value = 4;
      break;
    case savedAA:
      x.type = o_mem;
      x.dtyp = dt_byte;
      x.addr = ~0xFF | code3;
      trimaddr(x);
      break;
    case j8:
      x.offb = (uchar)cmd.size;
      x.type = o_near;
      x.dtyp = dt_code;
      {
        signed char disp = ua_next_byte();
        x.addr = cmd.ip + cmd.size + disp;
        x.addr &= ~1;
      }
      break;
    case j16:
      x.offb = (uchar)cmd.size;
      x.type = o_near;
      x.dtyp = dt_code;
      {
        signed short disp = ua_next_word();
        x.addr = cmd.ip + cmd.size + disp;
        x.addr &= ~1;
        cmd.auxpref |= aux_disp16;
      }
      break;
    case aa8:
      x.offb = (uchar)cmd.size;
      x.type = o_mem;
      x.dtyp = calc_dtyp(flags);
      x.addr = ~0xFF | ua_next_byte();
      trimaddr(x);
      break;
    case ai8:
      x.offb = (uchar)cmd.size;
      x.type = o_memind;
      x.dtyp = advanced() ? dt_dword : dt_word;
      x.addr = ua_next_byte();
      break;
    case aa16:
      x.type = o_mem;
      x.dtyp = calc_dtyp(flags);
      get_disp(x, false);
      trimaddr(x);
      break;
    case aa32:
      x.type = o_mem;
      x.dtyp = calc_dtyp(flags);
      get_disp(x, true);
      break;
    case aa24:          // 24bit address (16bit in !advanced())
      x.offb = (uchar)cmd.size;
      x.type = o_near;
      x.dtyp = calc_dtyp(flags);
      {
        uint32 high = ua_next_byte();
        if ( !advanced() && high != 0 ) return false;
        x.addr = (high << 16) | ua_next_word();
        cmd.auxpref |= advanced() ? aux_disp24 : aux_disp16;
      }
      break;
    case d16:           // @(d:16, ERs)
      opdsp16(x, calc_dtyp(flags));
      break;
    default:
      interr("h8 op");
  }
  return true;
}

//--------------------------------------------------------------------------
// 01 4?
static bool map014(void)
{
  switch ( code )
  {
    case 0x40:
      opreg8(cmd.Op2, CCR);
      break;
    case 0x41:
      opreg8(cmd.Op2, EXR);
      break;
    default:
      return false;
  }

  cmd.itype = H8_ldc;
  code = ua_next_byte();
  char dtyp = dt_word;
  switch ( code )
  {
    case 0x04:
      cmd.itype = H8_orc;
      dtyp = dt_byte;
      opimm8(cmd.Op1);
      break;
    case 0x05:
      cmd.itype = H8_xorc;
      dtyp = dt_byte;
      opimm8(cmd.Op1);
      break;
    case 0x06:
      cmd.itype = H8_andc;
      dtyp = dt_byte;
      opimm8(cmd.Op1);
      break;
    case 0x07:
      dtyp = dt_byte;
      opimm8(cmd.Op1);
      break;
    case 0x69:
      code = ua_next_byte();
      if ( code & 0x0F ) return false;
      opatHL(cmd.Op1, dtyp);
      break;
    case 0x6B:
      cmd.Op1.type = o_mem;
      cmd.Op1.dtyp = dtyp;
      code = ua_next_byte();
      switch ( code & 0x70 )
      {
        case 0x00:
          get_disp(cmd.Op1, false);
          break;
        case 0x20:
          get_disp(cmd.Op1, true);
          break;
        default:
          return false;
      }
      trimaddr(cmd.Op1);
      break;
    case 0x6D:
      code = ua_next_byte();
      if ( code & 0x0F ) return false;
      oppost(cmd.Op1, r0() + ((code>>4) & 7),  dtyp);
      break;
    case 0x6F:
      code = ua_next_byte();
      if ( code & 0x0F ) return false;
      opdsp16(cmd.Op1, dtyp);
      break;
    case 0x78:
      code = ua_next_byte();
      if ( code & 0x8F ) return false;
      if ( ua_next_byte() != 0x6B ) return false;
      code3 = ua_next_byte();
      if ( (code3 & 0x70) != 0x20 ) return false;
      opdsp32(cmd.Op1, dtyp);
      code = code3;
      break;
    default:
      return false;
  }
  if ( cmd.itype == H8_ldc )
    cmd.auxpref |= (dtyp == dt_word) ? aux_word : aux_byte;
  return true;
}

//--------------------------------------------------------------------------
// 6A 1?
// 6A 3?
static bool map4(void)
{
  uchar pref = code;
  cmd.Op2.type = o_mem;
  cmd.Op2.dtyp = dt_byte;
  get_disp(cmd.Op2, pref >= 0x30);
  trimaddr(cmd.Op2);
  uchar pcode = ua_next_byte();
  code = ua_next_byte();
  if ( code & 0x0F ) return false;
  if ( pcode >= 0x60 && pcode <= 0x63 )
  {
    opreg8(cmd.Op1, R0H + (code >> 4));
  }
  else
  {
    cmd.Op1.type = o_imm;
    cmd.Op1.dtyp = dt_byte;
    cmd.Op1.value = (code >> 4) & 7;
    if( pcode >= 0x70 && pcode <= 0x73 )
      if ( code & 0x80 ) return false;
  }
  switch ( pref )
  {
    case 0x10:
    case 0x30:
      switch ( pcode )
      {
        case 0x63:
        case 0x73:
          cmd.itype = H8_btst;
          break;
        case 0x74:
          cmd.itype = H8_bor;
          break;
        case 0x75:
          cmd.itype = H8_bxor;
          break;
        case 0x76:
          cmd.itype = H8_band;
          break;
        case 0x77:
          cmd.itype = H8_bld;
          break;
        default:
          return false;
      }
      break;

    case 0x18:
    case 0x38:
      switch ( pcode )
      {
        case 0x60:
        case 0x70:
          cmd.itype = H8_bset;
          break;
        case 0x61:
        case 0x71:
          cmd.itype = H8_bnot;
          break;
        case 0x62:
        case 0x72:
          cmd.itype = H8_bclr;
          break;
        case 0x67:
          cmd.itype = H8_bst;
          break;
      }
      break;

    default:
      return false;
  }
  return true;
}

#if 0
int ana(void)
{
  int _ana(void);
  msg("%a: before\n", cmd.ea);
  int code = _ana();
  msg("%a: after\n", cmd.ea);
  return code;
}
#endif
//--------------------------------------------------------------------------
int idaapi ana(void)
{
  code = ua_next_byte();
  uchar code0 = code;

  char dtyp;
  int index = code;
  map_t *m = map;
  int i = -1;
  bool noswap = false;
  while ( 1 )
  {
    uint32 p3;
    m += index;
    if ( (m->proc & ptype) == 0 ) return 0;
    cmd.itype = m->itype;
    switch ( cmd.itype )
    {
      case H8_null:
        return 0;

      case H8_eepmov:           // 5C 59 8F - byte
                                // D4 59 8F - word
        code = ua_next_byte();
        if ( code == 0x5C )
          cmd.auxpref |= aux_byte;
        else if ( code == 0xD4 )
          cmd.auxpref |= aux_word;
        else
          return 0;
        if ( ua_next_byte() != 0x59 || ua_next_byte() != 0x8F ) return 0;
        break;

      case H8_ldm:              // 01 [123]?
        if ( !advanced() ) return false;
        if ( code & 15 ) return 0;
        cmd.Op2.nregs  = (code >> 4) + 1;
        if ( ua_next_byte() != 0x6D ) return 0;
        code = ua_next_byte();
        if ( (code & 0x78) != 0x70 ) return 0;
        cmd.auxpref |= aux_long;                // .l
        cmd.Op1.type   = o_phrase;
        cmd.Op1.phtype = ph_post;
        cmd.Op1.dtyp   = dt_dword;
        cmd.Op1.phrase = ER7;
        cmd.Op2.type   = o_reglist;
        cmd.Op2.dtyp   = dt_dword;
        cmd.Op2.reg    = ER0 + (code & 7);
        if ( (code & 0x80) == 0 ) cmd.Op2.reg -= cmd.Op2.nregs - 1;
        switch ( cmd.Op2.nregs )
        {
          case 2:
            if ( cmd.Op2.reg != ER0
              && cmd.Op2.reg != ER2
              && cmd.Op2.reg != ER4
              && cmd.Op2.reg != ER6 ) return 0;
            break;
          case 3:
          case 4:
            if ( cmd.Op2.reg != ER0
              && cmd.Op2.reg != ER4 ) return 0;
            break;
        }
        break;

      case H8_mac:              // 01 6?
        if ( code & 15 ) return 0;
        if ( ua_next_byte() != 0x6D ) return 0;
        code = ua_next_byte();
        if ( code & 0x88 ) return 0;
        oppost(cmd.Op1, ER0 + ((code>>4) & 7),  dt_dword);
        oppost(cmd.Op2, ER0 + ( code     & 7),  dt_dword);
        break;

      case H8_mov:
        if ( (m->op1 & MANUAL) == 0 )
        {
          if ( code0 == 0xC || code0 == 0xD ) noswap = true;
          break;
        }
        switch ( code )
        {
          case 0x00:            // 01 0?
            if ( !advanced() ) return false;
            cmd.auxpref |= aux_long;
            dtyp = dt_dword;
            switch ( ua_next_byte() )
            {
              case 0x69:
                code = ua_next_byte();
                if ( code & 0x08 ) return 0;
                opatHL(cmd.Op1, dtyp);
                opreg(cmd.Op2, code & 7, dtyp);
                break;
              case 0x6B:
                goto MOVABS;
              case 0x6D:
                goto MOVPOST;
              case 0x6F:
                code = ua_next_byte();
                opdsp16(cmd.Op1, dtyp);
                opreg(cmd.Op2, code & 7, dtyp);
                break;
              case 0x78:
                code = ua_next_byte();
                if ( code & 0x0F ) return 0;
                if ( ua_next_byte() != 0x6B ) return 0;
                goto MOVDISP32;
              default:
                return 0;
            }
            break;
          case 0x6B:            // mov.w @aa, Rd
            cmd.auxpref |= aux_word;
            dtyp = dt_word;
MOVABS:
            code = ua_next_byte();
            cmd.Op1.type = o_mem;
            cmd.Op1.dtyp = dtyp;
            switch ( (code >> 4) & 7 )
            {
              case 0x0:
                get_disp(cmd.Op1, false);
                break;
              case 0x2:
                get_disp(cmd.Op1, true);
                break;
              default:
                return 0;
            }
            trimaddr(cmd.Op1);
            opreg(cmd.Op2, code & 15, dtyp);
            break;
          case 0x6C:            // byte  mov.b @ERs+, Rd
            dtyp = dt_byte;
            cmd.auxpref |= aux_byte;
            goto MOVPOST;
          case 0x6D:            // word  mov.w @ERs+, Rd
            dtyp = dt_word;
            cmd.auxpref |= aux_word;
MOVPOST:
            code = ua_next_byte();
            if ( dtyp == dt_dword && (code & 0x08) ) return 0;
            switch ( code & 0xF0 )
            {
              case 0x70:        // pop
                cmd.itype = H8_pop;
                opreg(cmd.Op1, (code & 15), dtyp);
                break;
              case 0xF0:        // push
                cmd.itype = H8_push;
                opreg(cmd.Op1, (code & 15), dtyp);
                break;
              default:          // mov
                oppost(cmd.Op1, r0() + ((code>>4) & 7),  dtyp);
                opreg(cmd.Op2, (code & 15), dtyp);
                break;
            }
            break;
          case 0x78:            // 78 ?0 6A 2?
            {
              code = ua_next_byte();
              if ( code & 0x8F ) return 0;
              switch ( ua_next_byte() )
              {
                case 0x6A:        // byte
                  cmd.auxpref |= aux_byte;
                  dtyp = dt_byte;
                  break;
                case 0x6B:        // word
                  dtyp = dt_word;
                  cmd.auxpref |= aux_word;
                  break;
                default:
                  return 0;
              }
MOVDISP32:
              code3 = ua_next_byte();
              if ( (code3 & 0x70) != 0x20 ) return 0;
              opdsp32(cmd.Op1, dtyp);
              opreg(cmd.Op2, code3 & 15, dtyp);
              code = code3;       // to swap operands if required
            }
            break;
          default:
            return 0;
        }
        break;

      case H8_rte:
      case H8_rts:
        if ( ua_next_byte() != 0x70 ) return 0;
        break;

      case H8_tas:
        if ( code != 0xE0 ) return 0;
        if ( ua_next_byte() != 0x7B ) return 0;
        code = ua_next_byte();
        if ( (code & 0x8F) != 0x0C ) return 0;
        opatHL(cmd.Op1, dt_byte);
        break;

      case H8_trapa:
        code = ua_next_byte();
        if ( (code & 0xC3) != 0x0 ) return 0;
        cmd.Op1.type = o_imm;
        cmd.Op1.dtyp = dt_byte;
        cmd.Op1.value = code >> 4;
        break;

      case MAP2:
        for ( i=0; i < qnumber(map2); i++ )
          if ( map2[i].prefix == code ) break;
        if ( i == qnumber(map2) ) interr("h8 map2");
        m = map2[i].map;
        code = ua_next_byte();
        index = code >> 4;
        continue;

      case MAP3:
        if ( i == -1 )
        {
          code3 = ua_next_byte();
          p3 = (code << 12);
        }
        else
        {
          code3 = code;
          p3 = (map2[i].prefix << 12);
        }
        code = ua_next_byte();
        p3 |= (code3<<4) | (code>>4);
        for ( i=0; i < qnumber(map3); i++ )
          if ( map3[i].prefix == (p3 & ~map3[i].mask) ) break;
        if ( i == qnumber(map3) ) return 0;
        m = map3[i].map;
        index = code & 7;
        continue;

      case MAP4:
        if ( !map4() ) return 0;
        break;

      case MAP014:
        if ( !map014() ) return 0;
        break;
    }
    break;
  }

  // m points to the target map entry
  if ( (m->op1 & X) == 0 ) switch ( m->op1 & CMD_SIZE )
  {
    case B: cmd.auxpref |= aux_byte; break;
    case W: cmd.auxpref |= aux_word; break;
    case L: cmd.auxpref |= aux_long; break;
    case V: cmd.auxpref |= advanced() ? aux_long : aux_word; break;
  }
  if ( !read_operand(cmd.Op1, m->op1) ) return 0;
  if ( !read_operand(cmd.Op2, m->op2) ) return 0;

  if ( code & 0x80 ) switch ( cmd.itype )
  {
    case H8_bor:  cmd.itype = H8_bior;   break;
    case H8_bxor: cmd.itype = H8_bixor;  break;
    case H8_band: cmd.itype = H8_biand;  break;
    case H8_bld:  cmd.itype = H8_bild;   break;
    case H8_bst:  cmd.itype = H8_bist;   break;
    case H8_btst:
    case H8_bset:
    case H8_bnot:
    case H8_bclr:
      if ( cmd.Op1.type == o_imm ) return 0;
      break;
    case H8_ldc:
      cmd.itype = H8_stc;
      goto SWAP;
    case H8_ldm:
      cmd.itype = H8_stm;
    case H8_mov:
SWAP:
      if ( !noswap )
      {
        op_t x = cmd.Op1;
        cmd.Op1 = cmd.Op2;
        cmd.Op2 = x;
        if ( cmd.Op2.type == o_imm ) return 0;
        if ( cmd.Op2.type == o_phrase && cmd.Op2.phtype == ph_post )
          cmd.Op2.phtype = ph_pre;
      }
      break;
  }
  return cmd.size;
}

