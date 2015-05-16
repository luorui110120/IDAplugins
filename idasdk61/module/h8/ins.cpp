/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "h8.hpp"

instruc_t Instructions[] = {

{ "",           0                               },      // Unknown Operation

{ "add",        CF_USE1|CF_USE2|CF_CHG2         },      // Add binary
{ "adds",       CF_USE1|CF_USE2|CF_CHG2         },      // Add with sign extension
{ "addx",       CF_USE1|CF_USE2|CF_CHG2         },      // Add with extend carry
{ "and",        CF_USE1|CF_USE2|CF_CHG2         },      // Logical AND
{ "andc",       CF_USE1|CF_USE2|CF_CHG2         },      // Logical AND with control register
{ "band",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit AND
{ "bra",        CF_USE1|CF_STOP                 },      // Branch always
{ "brn",        CF_USE1                         },      // Branch never
{ "bhi",        CF_USE1                         },      // Branch if higher
{ "bls",        CF_USE1                         },      // Branch if lower or same
{ "bcc",        CF_USE1                         },      // Branch if carry clear (higher or same)
{ "bcs",        CF_USE1                         },      // Branch if carry set (lower)
{ "bne",        CF_USE1                         },      // Branch if not equal
{ "beq",        CF_USE1                         },      // Branch if equal
{ "bvc",        CF_USE1                         },      // Branch if overflow clear
{ "bvs",        CF_USE1                         },      // Branch if overflow set
{ "bpl",        CF_USE1                         },      // Branch if plus
{ "bmi",        CF_USE1                         },      // Branch if minus
{ "bge",        CF_USE1                         },      // Branch if greates or equal
{ "blt",        CF_USE1                         },      // Branch if less
{ "bgt",        CF_USE1                         },      // Branch if greater
{ "ble",        CF_USE1                         },      // Branch if less or equal
{ "bclr",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit clear
{ "biand",      CF_USE1|CF_USE2|CF_CHG2         },      // Bit invert AND
{ "bild",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit invert load
{ "bior",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit invert OR
{ "bist",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit invert store
{ "bixor",      CF_USE1|CF_USE2|CF_CHG2         },      // Bit invert XOR
{ "bld",        CF_USE1|CF_USE2                 },      // Bit load
{ "bnot",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit NOT
{ "bor",        CF_USE1|CF_USE2|CF_CHG2         },      // Bit OR
{ "bset",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit set
{ "bsr",        CF_USE1|CF_CALL                 },      // Branch to subroutine
{ "bst",        CF_USE1|CF_USE2|CF_CHG2         },      // Bit store
{ "btst",       CF_USE1|CF_USE2                 },      // Bit test
{ "bxor",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit XOR
{ "clrmac",     0                               },      // Clear MAC register
{ "cmp",        CF_USE1|CF_USE2                 },      // Compare
{ "daa",        CF_USE1|CF_CHG1                 },      // Decimal adjust add
{ "das",        CF_USE1|CF_CHG1                 },      // Decimal adjust subtract
{ "dec",        CF_USE1                         },      // Decrement
{ "divxs",      CF_USE1|CF_USE2|CF_CHG2         },      // Divide extended as signed
{ "divxu",      CF_USE1|CF_USE2|CF_CHG2         },      // Divide extended as unsigned
{ "eepmov",     0                               },      // Move data to EEPROM
{ "exts",       CF_USE1|CF_CHG1                 },      // Extend as signed
{ "extu",       CF_USE1|CF_CHG1                 },      // Extend as unsigned
{ "inc",        CF_USE1                         },      // Increment
{ "jmp",        CF_USE1|CF_STOP                 },      // Jump
{ "jsr",        CF_USE1|CF_CALL                 },      // Jump to subroutine
{ "ldc",        CF_USE1|CF_CHG2                 },      // Load to control register
{ "ldm",        CF_USE1|CF_CHG2                 },      // Load to multiple registers
{ "ldmac",      CF_USE1|CF_CHG2                 },      // Load to MAC register
{ "mac",        CF_USE1|CF_USE2                 },      // Multiply and accumulate
{ "mov",        CF_USE1|CF_CHG2                 },      // Move data
{ "movfpe",     CF_USE1|CF_CHG2                 },      // Move from peripheral with E clock
{ "movtpe",     CF_USE1|CF_CHG2                 },      // Move to peripheral with E clock
{ "mulxs",      CF_USE1|CF_USE2|CF_CHG2         },      // Multiply extend as signed
{ "mulxu",      CF_USE1|CF_USE2|CF_CHG2         },      // Multiply extend as unsigned
{ "neg",        CF_USE1|CF_CHG1                 },      // Negate
{ "nop",        0                               },      // No operation
{ "not",        CF_USE1|CF_CHG1                 },      // Logical complement
{ "or",         CF_USE1|CF_USE2|CF_CHG2         },      // Logical OR
{ "orc",        CF_USE1|CF_USE2|CF_CHG2         },      // Logical OR with control register
{ "pop",        CF_CHG1                         },      // Pop data from stack
{ "push",       CF_USE1                         },      // Push data on stack
{ "rotl",       CF_USE1                         },      // Rotate left
{ "rotr",       CF_USE1                         },      // Rotate right
{ "rotxl",      CF_USE1                         },      // Rotate with extend carry left
{ "rotxr",      CF_USE1                         },      // Rotate with extend carry right
{ "rte",        CF_STOP                         },      // Return from exception
{ "rts",        CF_STOP                         },      // Return from subroutine
{ "shal",       CF_USE1                         },      // Shift arithmetic left
{ "shar",       CF_USE1                         },      // Shift arithmetic right
{ "shll",       CF_USE1                         },      // Shift logical left
{ "shlr",       CF_USE1                         },      // Shift logical right
{ "sleep",      0                               },      // Power down mode
{ "stc",        CF_USE1|CF_CHG2                 },      // Store from control register
{ "stm",        CF_USE1|CF_CHG2                 },      // Store from multiple registers
{ "stmac",      CF_USE1|CF_CHG2                 },      // Store from MAC register
{ "sub",        CF_USE1|CF_USE2|CF_CHG2         },      // Subtract binary
{ "subs",       CF_USE1|CF_USE2|CF_CHG2         },      // Subtract with sign extension
{ "subx",       CF_USE1|CF_USE2|CF_CHG2         },      // Subtract with extend carry
{ "tas",        CF_USE1|CF_CHG1                 },      // Test and set
{ "trapa",      CF_USE1                         },      // Trap always
{ "xor",        CF_USE1|CF_USE2|CF_CHG2         },      // Logical XOR
{ "xorc",       CF_USE1|CF_USE2|CF_CHG2         },      // Logical XOR with control register

};

CASSERT(qnumber(Instructions) == H8_last);
