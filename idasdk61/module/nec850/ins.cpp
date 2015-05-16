/*
*      Interactive disassembler (IDA).
*      Copyright (c) 1990-2009 Hex-Rays
*      ALL RIGHTS RESERVED.
*
*/

#include "ins.hpp"

instruc_t Instructions[NEC850_LAST_INSTRUCTION] =
{
  { "", 0 }, // Unknown Operation
  { "breakpoint", CF_STOP }, // undefined instruction
  { "xori", CF_USE1|CF_USE2|CF_CHG3 }, // Exclusive Or Immediate
  { "xor", CF_USE1|CF_USE2|CF_CHG2 }, // Exclusive OR
  { "tst1", CF_USE1|CF_USE2 }, // Test bit
  { "tst", CF_USE1|CF_USE2 }, // Test
  { "trap", CF_USE1 }, // Software trap
  { "subr", CF_USE1|CF_USE2|CF_CHG2 }, // Substract reverse
  { "sub", CF_USE1|CF_USE2|CF_CHG2 }, // Substract
  { "stsr", CF_USE1|CF_CHG2 }, // Store Contents of System Register
  { "st.b", CF_USE1|CF_USE2|CF_CHG2 }, // Store byte
  { "st.h", CF_USE1|CF_USE2|CF_CHG2 }, // Store half-word
  { "st.w", CF_USE1|CF_USE2|CF_CHG2 }, // Store word
  { "sst.b", CF_USE1|CF_USE2|CF_CHG2 }, // Store byte (use EP)
  { "sst.h", CF_USE1|CF_USE2|CF_CHG2 }, // Store half-word (use EP)
  { "sst.w", CF_USE1|CF_USE2|CF_CHG2 }, // Store word (use EP)
  { "sld.b", CF_USE1|CF_CHG2 }, // Load byte (use EP)
  { "sld.h", CF_USE1|CF_CHG2 }, // Load half-word (use EP)
  { "sld.w", CF_USE1|CF_CHG2 }, // Load word (use EP)
  { "shr", CF_USE1|CF_USE2|CF_CHG2|CF_SHFT }, // Shift Logical Right
  { "shl", CF_USE1|CF_USE2|CF_CHG2|CF_SHFT }, // Shift Logical Left
  { "set1", CF_USE1|CF_USE2|CF_CHG2 }, // Set Bit
  { "setfv", CF_CHG1 }, // The general register is set to 1 if the condition "overflow" is satisfied
  { "setfl", CF_CHG1 }, // The general register is set to 1 if the condition "less" is satisfied
  { "setfz", CF_CHG1 }, // The general register is set to 1 if the condition "zero" is satisfied
  { "setfnh", CF_CHG1 }, // The general register is set to 1 if the condition "not higher" is satisfied
  { "setfn", CF_CHG1 }, // The general register is set to 1 if the condition "negative" is satisfied
  { "setft", CF_CHG1 }, // The general register is set to 1 if the condition "always" is satisfied
  { "setflt", CF_CHG1 }, // The general register is set to 1 if the condition "less than (signed)" is satisfied
  { "setfle", CF_CHG1 }, // The general register is set to 1 if the condition "less than or equal (signed)" is satisfied
  { "setfnv", CF_CHG1 }, // The general register is set to 1 if the condition "no overflow" is satisfied
  { "setfnc", CF_CHG1 }, // The general register is set to 1 if the condition "no carry" is satisfied
  { "setfnz", CF_CHG1 }, // The general register is set to 1 if the condition "not zero" is satisfied
  { "setfh", CF_CHG1 }, // The general register is set to 1 if the condition "higher than" is satisfied
  { "setfp", CF_CHG1 }, // The general register is set to 1 if the condition "positive" is satisfied
  { "setfsa", CF_CHG1 }, // The general register is set to 1 if the condition "saturated" is satisfied
  { "setfge", CF_CHG1 }, // The general register is set to 1 if the condition "greater than or equal (signed)" is satisfied
  { "setfgt", CF_CHG1 }, // The general register is set to 1 if the condition "greater than (signed)" is satisfied
  { "satsubr", CF_USE1|CF_USE2|CF_CHG2 }, // Saturated Subtract Reverse
  { "satsubi", CF_USE1|CF_USE2|CF_CHG3 }, // Saturated Subtract Immediate
  { "satsub", CF_USE1|CF_USE2|CF_CHG2 }, // Saturated Subtract
  { "satadd", CF_USE1|CF_USE2|CF_CHG2 }, // Saturated Add
  { "sar", CF_USE1|CF_USE2|CF_CHG2|CF_SHFT }, // Shift Arithmetic Right
  { "reti", CF_STOP }, // Return from Trap or Interrupt
  { "ori", CF_USE1|CF_USE2|CF_CHG2 }, // OR immediate
  { "or", CF_USE1|CF_USE2|CF_CHG2 }, // OR
  { "not1", CF_USE1|CF_USE2|CF_CHG2 }, // Not Bit
  { "not", CF_USE1|CF_USE2|CF_CHG2 }, // Not
  { "nop", 0 }, // No Operation
  { "mulhi", CF_USE1|CF_USE2|CF_CHG3 }, // Multiply Half-Word Immediate
  { "mulh", CF_USE1|CF_USE2|CF_CHG2 }, // Multiply Half-Word
  { "movhi", CF_USE1|CF_USE2|CF_CHG3 }, // Move High Half-Word
  { "movea", CF_USE1|CF_USE2|CF_CHG3 }, // Move Effective Address
  { "mov", CF_USE1|CF_CHG2 }, // Move
  { "ldsr", CF_USE1|CF_CHG2 }, // Load to system register
  { "ld.b", CF_USE1|CF_CHG2 }, // Load byte
  { "ld.h", CF_USE1|CF_CHG2 }, // Load half-word
  { "ld.w", CF_USE1|CF_CHG2 }, // Load word
  { "jr", CF_USE1|CF_STOP }, // Jump Relative
  { "jmp", CF_USE1|CF_JUMP|CF_STOP}, // Jump Register
  { "jarl", CF_CALL|CF_USE1|CF_CHG2 }, // Jump and Register Link
  { "halt", CF_STOP }, // Halt
  { "ei", 0 }, // Enable interrupt
  { "divh", CF_USE1|CF_USE2|CF_CHG2 }, // Divide Half-Word
  { "di", 0 }, // Disable Interrupt
  { "cmp", CF_USE1|CF_USE2 }, // Compare
  { "clr1", CF_USE1|CF_USE2|CF_CHG2 }, // Clear bit
  { "bv", CF_USE1 }, // Branch if overflow
  { "bl", CF_USE1 }, // Branch if less
  { "bz", CF_USE1 }, // Branch if zero
  { "bnh", CF_USE1 }, // Branch if not higher
  { "bn", CF_USE1 }, // Branch if negative
  { "br", CF_USE1 | CF_STOP}, // Branch if always
  { "blt", CF_USE1 }, // Branch if less than (signed)
  { "ble", CF_USE1 }, // Branch if less than or equal (signed)
  { "bnv", CF_USE1 }, // Branch if no overflow
  { "bnc", CF_USE1 }, // Branch if no carry
  { "bnz", CF_USE1 }, // Branch if not zero
  { "bh", CF_USE1 }, // Branch if higher than
  { "bp", CF_USE1 }, // Branch if positive
  { "bsa", CF_USE1 }, // Branch if saturated
  { "bge", CF_USE1 }, // Branch if greater than or equal (signed)
  { "bgt", CF_USE1 }, // Branch if greater than (signed)
  { "andi", CF_USE1|CF_USE2|CF_CHG3 }, // And immediate
  { "and", CF_USE1|CF_USE2|CF_CHG2 }, // And
  { "addi", CF_USE1|CF_USE2|CF_CHG3 }, // Add Immediate
  { "add", CF_USE1|CF_USE2|CF_CHG2 }, // Add
  //
  // V850E
  //
  { "switch", CF_USE1|CF_STOP|CF_JUMP}, // Jump with table look up
  { "zxb", CF_USE1|CF_CHG1 }, //
  { "sxb", CF_USE1|CF_CHG1 }, //
  { "zxh", CF_USE1|CF_CHG1 }, //
  { "sxh", CF_USE1|CF_CHG1 }, //
  { "dispose", CF_USE1|CF_USE2 }, //
  { "dispose", CF_USE1|CF_USE2|CF_USE3|CF_STOP }, //
  { "callt", CF_USE1|CF_CALL }, //
  { "dbtrap", CF_STOP }, //
  { "dbret", CF_STOP }, //
  { "ctret", CF_STOP }, //

  { "sasfv", CF_USE1|CF_CHG1 }, // Shift and set "overflow" condition
  { "sasfl", CF_USE1|CF_CHG1 }, // Shift and set "less" condition
  { "sasfz", CF_USE1|CF_CHG1 }, // Shift and set "zero" condition
  { "sasfnh", CF_USE1|CF_CHG1 }, // Shift and set "not higher" condition
  { "sasfn", CF_USE1|CF_CHG1 }, // Shift and set "negative" condition
  { "sasft", CF_USE1|CF_CHG1 }, // Shift and set "always" condition
  { "sasflt", CF_USE1|CF_CHG1 }, // Shift and set "less than (signed)" condition
  { "sasfle", CF_USE1|CF_CHG1 }, // Shift and set "less than or equal (signed)" condition
  { "sasfnv", CF_USE1|CF_CHG1 }, // Shift and set "no overflow" condition
  { "sasfnc", CF_USE1|CF_CHG1 }, // Shift and set "no carry" condition
  { "sasfnz", CF_USE1|CF_CHG1 }, // Shift and set "not zero" condition
  { "sasfh", CF_USE1|CF_CHG1 }, // Shift and set "higher than" condition
  { "sasfp", CF_USE1|CF_CHG1 }, // Shift and set "positive" condition
  { "sasfsa", CF_USE1|CF_CHG1 }, // Shift and set "saturated" condition
  { "sasfge", CF_USE1|CF_CHG1 }, // Shift and set "greater than or equal (signed)" condition
  { "sasfgt", CF_USE1|CF_CHG1 }, // Shift and set "greater than (signed)" condition

  { "prepare", CF_USE1|CF_USE2|CF_USE3 }, // Function prepare
  { "prepare", CF_USE1|CF_USE2 }, // Function prepare

  { "mul", CF_USE1|CF_USE2|CF_CHG2|CF_CHG3 }, // Multiply word
  { "mulu", CF_USE1|CF_USE2|CF_CHG2|CF_CHG3 }, // Multiply word unsigned

  { "divh", CF_USE1|CF_USE2|CF_CHG2|CF_CHG3 }, // Divide halfword
  { "divhu", CF_USE1|CF_USE2|CF_CHG2|CF_CHG3 }, // Divide halfword unsigned
  { "div", CF_USE1|CF_USE2|CF_CHG2|CF_CHG3 }, // Divide word
  { "divu", CF_USE1|CF_USE2|CF_CHG2|CF_CHG3 }, // Divide word unsigned


  { "bsw", CF_USE1|CF_CHG2 }, // Byte swap word
  { "bsh", CF_USE1|CF_CHG2 }, // Byte swap halfword
  { "hsw", CF_USE1|CF_CHG2 }, // Halfword swap word

  { "cmovv", CF_USE1|CF_USE2|CF_CHG3 }, // Conditional move (overflow)
  { "cmovl", CF_USE1|CF_USE2|CF_CHG3 }, // Conditional move (less)
  { "cmovz", CF_USE1|CF_USE2|CF_CHG3 }, // Conditional move (zero)
  { "cmovnh", CF_USE1|CF_USE2|CF_CHG3 }, // Conditional move (not higher)
  { "cmovn", CF_USE1|CF_USE2|CF_CHG3 }, // Conditional move (negative)
  { "cmov", CF_USE1|CF_USE2|CF_CHG3 }, // Conditional move (always)
  { "cmovlt", CF_USE1|CF_USE2|CF_CHG3 }, // Conditional move (less than (signed))
  { "cmovle", CF_USE1|CF_USE2|CF_CHG3 }, // Conditional move (less than or equal (signed))
  { "cmovnv", CF_USE1|CF_USE2|CF_CHG3 }, // Conditional move (no overflow)
  { "cmovnc", CF_USE1|CF_USE2|CF_CHG3 }, // Conditional move (no carry)
  { "cmovnz", CF_USE1|CF_USE2|CF_CHG3 }, // Conditional move (not zero)
  { "cmovh", CF_USE1|CF_USE2|CF_CHG3 }, // Conditional move (higher than)
  { "cmovp", CF_USE1|CF_USE2|CF_CHG3 }, // Conditional move (positive)
  { "cmovsa", CF_USE1|CF_USE2|CF_CHG3 }, // Conditional move (saturated)
  { "cmovge", CF_USE1|CF_USE2|CF_CHG3 }, // Conditional move (greater than or equal (signed))
  { "cmovgt", CF_USE1|CF_USE2|CF_CHG3 }, // Conditional move (greater than (signed))

  { "sld.bu", CF_USE1|CF_CHG2 }, // Short format load byte unsigned
  { "sld.hu", CF_USE1|CF_CHG2 }, // Short format load halfword unsigned

  { "ld.bu", CF_USE1|CF_CHG2 }, // load byte unsigned
  { "ld.hu", CF_USE1|CF_CHG2 }, // load halfword unsigned
};

CASSERT(qnumber(Instructions) == NEC850_LAST_INSTRUCTION);
