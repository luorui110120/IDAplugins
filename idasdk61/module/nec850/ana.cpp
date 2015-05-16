/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Instruction decoder
 *
 */
#include "ins.hpp"

bool is_v850e = false;

//------------------------------------------------------------------------
// The instruction formats 5 to 10 have bit10 and bit9 on and are a word
// The rest of the instructions are half-word and their format is 1 to 4
int detect_inst_len(uint16 w)
{
  return ((w & 0x600) == 0x600) ? 4 : 2;
}

//------------------------------------------------------------------------
// Fetchs an instruction (uses ua_next_xxx()) of a correct size (ready for decoding)
// Returns the size of the instruction
int fetch_instruction(uint32 *w)
{
  uint16 hw = ua_next_word();
  int r = detect_inst_len(hw);
  if ( r == 4 )
    *w = (ua_next_word() << 16) | hw;
  else
    *w = hw;
  return r;
}

//------------------------------------------------------------------------
// Decodes an instruction "w" into cmd structure
bool decode_instruction(uint32 w, insn_t &cmd)
{
#define PARSE_L12 (((w & 1) << 11) | (w >> 21))
#define PARSE_R1  (w & 0x1F)
#define PARSE_R2  ((w & 0xF800) >> 11)

  typedef struct
  {
    int itype;
    int flags;
  } itype_flags_t;
  // If an instruction deals with displacement it should
  // initialize this pointer to the operand location.
  // At the end we will transform the operand to o_mem
  // if we know how to resolve its address
  op_t *displ_op = NULL;

  do
  {
    uint32 op;

    //
    // Format I
    //
    op = (w & 0x7E0) >> 5; // Take bit5->bit10
    if ( op <= 0xF )
    {
      static const int inst_1[] =
      {
        /* MOV reg1, reg2 */ NEC850_MOV,             /* NOT reg1, reg2 */ NEC850_NOT,
        /* DIVH  reg1, reg2 */ NEC850_DIVH,          /* JMP [reg1] */ NEC850_JMP,
        /* SATSUBR reg1, reg2 */ NEC850_SATSUBR,     /* SATSUB reg1, reg2 */ NEC850_SATSUB,
        /* SATADD reg1, reg2 */ NEC850_SATADD,       /* MULH reg1, reg2 */ NEC850_MULH,
        /* OR reg1, reg2 */ NEC850_OR,               /* XOR reg1, reg2 */ NEC850_XOR,
        /* AND reg1, reg2 */ NEC850_AND,             /* TST reg1, reg2 */ NEC850_TST,
        /* SUBR reg1, reg2 */ NEC850_SUBR,           /* SUB reg1, reg2 */ NEC850_SUB,
        /* ADD reg1, reg2 */ NEC850_ADD,             /* CMP reg1, reg2 */ NEC850_CMP
      };

      //
      // NOP, Equivalent to MOV R, r (where R=r=0)
      if ( w == 0 )
      {
        cmd.itype    = NEC850_NOP;
        cmd.Op1.type = o_void;
        cmd.Op1.dtyp = dt_void;
        break;
      }

      if ( is_v850e )
      {
        if ( w == 0xF840 )
        {
          cmd.itype = NEC850_DBTRAP;
          break;
        }
      }
      uint16 r1 = PARSE_R1;
      uint16 r2 = PARSE_R2;

      cmd.itype     = inst_1[op];
      cmd.Op1.reg   = r1;
      cmd.Op1.type  = o_reg;
      cmd.Op1.dtyp  = dt_dword;

      if ( is_v850e )
      {
        if ( r2 == 0 )
        {
          if ( cmd.itype == NEC850_DIVH )
          {
            cmd.itype = NEC850_SWITCH;
            break;
          }
          else if ( cmd.itype == NEC850_SATSUBR )
          {
            cmd.itype = NEC850_ZXB;
            break;
          }
          else if ( cmd.itype == NEC850_SATSUB )
          {
            cmd.itype = NEC850_SXB;
            break;
          }
          else if ( cmd.itype == NEC850_SATADD )
          {
            cmd.itype = NEC850_ZXH;
            break;
          }
          else if ( cmd.itype == NEC850_MULH )
          {
            cmd.itype = NEC850_SXH;
            break;
          }
        }
        // case when r2 != 0
        else
        {
          // SLD.BU / SLD.HU
          if ( cmd.itype == NEC850_JMP )
          {
            bool   sld_hu = (w >> 4) & 1;
            uint32 addr = w & 0xF;

            if ( sld_hu )
            {
              cmd.itype       = NEC850_SLD_HU;
              cmd.Op1.dtyp    = dt_word;
              addr          <<= 1;
            }
            else
            {
              cmd.itype       = NEC850_SLD_BU;
              cmd.Op1.dtyp    = dt_byte;
            }

            cmd.Op1.type      = o_displ;
            displ_op          = &cmd.Op1;
            cmd.Op1.reg       = rEP;
            cmd.Op1.addr      = addr;
            cmd.Op1.specflag1 = N850F_USEBRACKETS;

            cmd.Op2.type      = o_reg;
            cmd.Op2.reg       = r2;
            cmd.Op2.dtyp      = dt_dword;

            break;
          }
        }
      }
      if ( cmd.itype == NEC850_JMP && r2 == 0 )
      {
        cmd.Op1.specflag1 = N850F_USEBRACKETS;
      }
      else
      {
        cmd.Op2.reg   = r2;
        cmd.Op2.type  = o_reg;
        cmd.Op2.dtyp  = dt_dword;
      }
      break;
    }
    // Format II
    else if ( op >= 0x10 && op <= 0x17 )
    {
      // flag used for sign extension
      static const itype_flags_t inst_2[] =
      {
        { NEC850_MOV,    1 }, /* MOV imm5, reg2 */
        { NEC850_SATADD, 1},  /* SATADD imm5, reg2 */
        { NEC850_ADD,    1 }, /* ADD imm5, reg2 */
        { NEC850_CMP,    1 }, /* CMP imm5, reg2 */
        { NEC850_SHR,    0 }, /* SHR imm5, reg2 */
        { NEC850_SAR,    0 }, /* SAR imm5, reg2 */
        { NEC850_SHL,    0 }, /* SHL imm5, reg2 */
        { NEC850_MULH,   1 }, /* MULH imm5, reg2 */
      };
      op -= 0x10;

      cmd.itype = inst_2[op].itype;
      uint16 r2 = PARSE_R2;

      if ( is_v850e )
      {
        //
        // CALLT
        //
        if ( r2 == 0 && (cmd.itype == NEC850_SATADD || cmd.itype == NEC850_MOV) )
        {
          cmd.itype     = NEC850_CALLT;
          cmd.Op1.dtyp  = dt_byte;
          cmd.Op1.type  = o_imm;
          cmd.Op1.value = w & 0x3F;
          break;
        }
      }

      sval_t v = PARSE_R1;
      if ( inst_2[op].flags == 1 )
      {
        SIGN_EXTEND(sval_t, v, 5);
        cmd.Op1.specflag1 |= N850F_OUTSIGNED;
      }

      cmd.Op1.type  = o_imm;
      cmd.Op1.value = v;
      cmd.Op1.dtyp  = dt_byte;

      cmd.Op2.type  = o_reg;
      cmd.Op2.reg   = r2;
      cmd.Op2.dtyp  = dt_dword;

      // ADD imm, reg -> reg = reg + imm
      if ( cmd.itype == NEC850_ADD && r2 == rSP)
        cmd.auxpref |= N850F_SP;
      break;
    }
    // Format VI
    else if ( op >= 0x30 && op <= 0x37 )
    {
      static const itype_flags_t inst_6[] =
      {
        { NEC850_ADDI,      1 }, /* ADDI imm16, reg1, reg2 */
        { NEC850_MOVEA,     1 }, /* MOVEA imm16, reg1, reg2 */
        { NEC850_MOVHI,     0 }, /* MOVHI imm16, reg1, reg2 */
        { NEC850_SATSUBI,   1 }, /* SATSUBI imm16, reg1, reg2 */
        { NEC850_ORI,       0 }, /* ORI imm16, reg1, reg2 */
        { NEC850_XORI,      0 }, /* XORI imm16, reg1, reg2 */
        { NEC850_ANDI,      0 }, /* ANDI imm16, reg1, reg2 */
        { NEC850_MULHI,     0 }, /* MULHI  imm16, reg1, reg2 */
      };
      op -= 0x30;
      cmd.itype = inst_6[op].itype;

      uint16 r1     = PARSE_R1;
      uint16 r2     = PARSE_R2;
      uint32 imm    = w >> 16;

      //
      // V850E instructions
      if ( is_v850e && r2 == 0 )
      {
        // MOV imm32, R
        if ( cmd.itype == NEC850_MOVEA )
        {
          imm            |= ua_next_word() << 16;
          cmd.Op1.type    = o_imm;
          cmd.Op1.dtyp    = dt_dword;
          cmd.Op1.value   = imm;
          cmd.itype       = NEC850_MOV;

          cmd.Op2.type   = o_reg;
          cmd.Op2.reg    = r1;
          cmd.Op2.dtyp   = dt_dword;
          break;
        }
        // DISPOSE imm5, list12 (reg1 == 0)
        // DISPOSE imm5, list12, [reg1]
        else if ( cmd.itype == NEC850_SATSUBI || cmd.itype == NEC850_MOVHI )
        {
          uint16 r1 = (w >> 16) & 0x1F;
          uint16 L  = PARSE_L12;

          cmd.auxpref   |= N850F_SP; // SP reference

          cmd.Op1.value  = (w & 0x3E) >> 1;
          cmd.Op1.type   = o_imm;
          cmd.Op1.dtyp   = dt_byte;

          cmd.Op2.value  = L;
          cmd.Op2.type   = o_reglist;
          cmd.Op2.dtyp   = dt_word;

          if ( r1 != 0 )
          {
            cmd.Op3.dtyp = dt_dword;
            cmd.Op3.type = o_reg;
            cmd.Op3.reg  = r1;
            cmd.Op3.specflag1 = N850F_USEBRACKETS;

            cmd.itype = NEC850_DISPOSE_r;
          }
          else
          {
            cmd.itype = NEC850_DISPOSE_r0;
          }
          break;
        }
      }
      bool is_signed     = inst_6[op].flags == 1;
      cmd.Op1.type       = o_imm;
      cmd.Op1.dtyp       = dt_dword;
      cmd.Op1.value      = is_signed ? sval_t(int16(imm)) : imm;
      cmd.Op1.specflag1 |= N850F_OUTSIGNED;

      cmd.Op2.type       = o_reg;
      cmd.Op2.reg        = r1;
      cmd.Op2.dtyp       = dt_dword;

      cmd.Op3.type       = o_reg;
      cmd.Op3.reg        = r2;
      cmd.Op3.dtyp       = dt_dword;

      // (ADDI|MOVEA) imm, sp, sp -> sp = sp + imm
      if ( (cmd.itype == NEC850_ADDI || cmd.itype == NEC850_MOVEA)
        && ((r1 == rSP) && (r2 == rSP)) )
      {
        cmd.auxpref |= N850F_SP;
      }
      break;
    }
    // Format VII - LD.x
    else if ( op == 0x38 || op == 0x39 )
    {
      displ_op       = &cmd.Op1;
      cmd.Op1.type   = o_displ;
      cmd.Op1.phrase = PARSE_R1; // R

      cmd.Op2.type   = o_reg;
      cmd.Op2.reg    = PARSE_R2;
      cmd.Op2.dtyp   = dt_dword;

      uint32 addr;
      // LD.B
      if ( op == 0x38 )
      {
        addr          = w >> 16;
        cmd.itype     = NEC850_LD_B;
        cmd.Op1.dtyp  = dt_byte;
      }
      else
      {
        // Bit16 is cleared for LD.H
        if ( (w & (1 << 16)) == 0 )
        {
          cmd.itype      = NEC850_LD_H;
          cmd.Op1.dtyp   = dt_word;
        }
        // LD.W
        else
        {
          cmd.itype      = NEC850_LD_W;
          cmd.Op1.dtyp   = dt_dword;
        }
        addr = ((w & 0xFFFE0000) >> 17) << 1;
      }
      cmd.Op1.specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED;
      cmd.Op1.addr = int16(addr);

      break;
    }
    // Format VII - ST.x
    else if ( op == 0x3A || op == 0x3B )
    {
      // (1) ST.B  reg2, disp16 [reg1]
      // (2) ST.H  reg2, disp16 [reg1]
      // (3) ST.W  reg2, disp16 [reg1]
      cmd.Op1.type  = o_reg;
      cmd.Op1.reg   = PARSE_R2;
      cmd.Op1.dtyp  = dt_dword;

      cmd.Op2.type  = o_displ;
      displ_op      = &cmd.Op2;
      cmd.Op2.reg   = PARSE_R1;
      cmd.Op2.specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED;
      // ST.B
      uint32 addr;
      if ( op == 0x3A )
      {
        addr          = w >> 16;
        cmd.itype     = NEC850_ST_B;
        cmd.Op2.dtyp  = dt_byte;
      }
      else
      {
        // Bit16 is cleared for ST.H
        if ( (w & (1 << 16)) == 0 )
        {
          cmd.itype      = NEC850_ST_H;
          cmd.Op2.dtyp   = dt_word;
        }
        else
        {
          cmd.itype      = NEC850_ST_W;
          cmd.Op2.dtyp   = dt_dword;
        }
        addr = ((w & 0xFFFE0000) >> 17) << 1;
      }
      cmd.Op2.addr = int16(addr);
      break;
    }
    // Format XIII - PREPARE / LD.BU
    else if ( is_v850e
           && ((w >> 16) & 0x1) // this bit is important to differentiate between JARL/JR instructions
           && (op == 0x3C || op == 0x3D) )
    {
      uint16 r2 = PARSE_R2;

      uint16 subop = (w >> 16) & 0x1F;
      // PREPARE
      if ( r2 == 0 && (subop == 1 || (subop & 7) == 3) )
      {
        cmd.auxpref   |= N850F_SP;
        cmd.Op1.value  = PARSE_L12;
        cmd.Op1.type   = o_reglist;
        cmd.Op1.dtyp   = dt_word;

        cmd.Op2.value  = (w & 0x3E) >> 1;
        cmd.Op2.type   = o_imm;
        cmd.Op2.dtyp   = dt_byte;

        if ( subop == 1 )
        {
          cmd.itype = NEC850_PREPARE_i;
        }
        else
        {
          cmd.itype = NEC850_PREPARE_sp;
          uint16 ff = subop >> 2;
          switch ( ff )
          {
          case 0:
            // disassembles as: PREPARE list12, imm5, sp
            // meaning: load sp into ep
            cmd.Op3.dtyp  = dt_word;
            cmd.Op3.type  = o_reg;
            cmd.Op3.reg   = rSP; // stack pointer
            break;
            // the other cases disassemble with imm (the 3rd operand) directly processed:
            // f=1->ep=sign_extend(imm16), f=2->ep=imm16 shl 16, f=3->ep=imm32
          case 1:
            // c:   a8 07 0b 80     prepare {r24}, 20, 0x1
            //10:   01 00
            cmd.Op3.dtyp  = dt_word;
            cmd.Op3.type  = o_imm;
            cmd.Op3.value = sval_t(int16(ua_next_word()));
            break;
          case 2:
            //2:   a8 07 13 80     prepare {r24}, 20, 0x10000
            //6:   01 00
            cmd.Op3.dtyp = dt_word;
            cmd.Op3.type = o_imm;
            cmd.Op3.value = ua_next_word() << 16;
            break;
          case 3:
            //2:   a8 07 1b 80     prepare {r24}, 20, 0x1
            //6:   01 00 00 00
            cmd.Op3.dtyp = dt_dword;
            cmd.Op3.type = o_imm;
            cmd.Op3.value = ua_next_long();
            break;
          }
        }
      }
      // LD.BU
      else
      {
        uint16 r1 = PARSE_R1;

        cmd.itype = NEC850_LD_BU;

        cmd.Op1.type = o_displ;
        displ_op     = &cmd.Op1;
        cmd.Op1.reg  = r1;
        cmd.Op1.addr = int16( ((w >> 16) & ~1) | ((w & 0x20) >> 5) );
        cmd.Op1.dtyp = dt_byte;
        cmd.Op1.specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED;

        cmd.Op2.type = o_reg;
        cmd.Op2.dtyp = dt_dword;
        cmd.Op2.reg  = r2;
      }
      break;
    }
    // Format VIII
    else if ( op == 0x3E )
    {
      // parse sub-opcode (b15..b14)
      op = ((w & 0xC000) >> 14);
      static const int inst_8[] =
      {
        NEC850_SET1, NEC850_NOT1,
        NEC850_CLR1, NEC850_TST1
      };
      cmd.itype         = inst_8[op];
      cmd.Op1.type      = o_imm;
      cmd.Op1.value     = ((w & 0x3800) >> 11); // b13..b11
      cmd.Op1.dtyp      = dt_byte;

      cmd.Op2.type      = o_displ;
      displ_op          = &cmd.Op2;
      cmd.Op2.addr      = int16(w >> 16);
      cmd.Op2.offb      = 2;
      cmd.Op2.dtyp      = dt_byte;
      cmd.Op2.reg       = PARSE_R1; // R
      cmd.Op2.specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED;
      break;
    }
    //
    // Format IX, X
    //
    else if ( op == 0x3F )
    {
      //
      // Format X
      //

      // Const opcodes
      if ( w == 0x16087E0 ) // EI
        cmd.itype = NEC850_EI;
      else if ( w == 0x16007E0 ) // DI
        cmd.itype = NEC850_DI;
      else if ( w == 0x14007E0 ) // RETI
        cmd.itype = NEC850_RETI;
      else if ( w == 0x12007E0 ) // HALT
        cmd.itype = NEC850_HALT;
      else if ( w == 0xffffffff )
        cmd.itype = NEC850_BREAKPOINT;
      else if ( (w >> 5) == 0x8003F ) // TRAP
      {
        cmd.itype = NEC850_TRAP;
        cmd.Op1.type  = o_imm;
        cmd.Op1.value = PARSE_R1;
        cmd.Op1.dtyp  = dt_byte;
        break;
      }
      if ( cmd.itype != 0 )
        break;

      // Still in format 10 (op = 0x3F)
      if ( is_v850e )
      {
        if ( w == 0x14607E0 )
        {
          cmd.itype = NEC850_DBRET;
          break;
        }
        else if ( w == 0x14407E0 )
        {
          cmd.itype = NEC850_CTRET;
          break;
        }
        // LD.HU
        else if ( (w >> 16) & 0x1 )
        {
          cmd.itype         = NEC850_LD_HU;
          cmd.Op1.type      = o_displ;
          displ_op          = &cmd.Op1;
          cmd.Op1.reg       = PARSE_R1;
          cmd.Op1.addr      = (w >> 17) << 1;
          cmd.Op1.dtyp      = dt_word;
          cmd.Op1.specflag1 = N850F_USEBRACKETS;
          cmd.Op2.type      = o_reg;
          cmd.Op2.dtyp      = dt_dword;
          cmd.Op2.reg       = PARSE_R2;
          break;
        }
        //
        // Group match
        //
        op = (w & 0x7FF0000) >> 16;
        if ( op == 0x220 )
          cmd.itype = NEC850_MUL;
        else if ( op == 0x222 )
          cmd.itype = NEC850_MULU;
        else if ( op == 0x280 )
          cmd.itype = NEC850_DIVH_r3;
        else if ( op == 0x282 )
          cmd.itype = NEC850_DIVHU;
        else if ( op == 0x2C0 )
          cmd.itype = NEC850_DIV;
        else if ( op == 0x2C2 )
          cmd.itype = NEC850_DIVU;
        // process the match
        if ( cmd.itype != 0 )
        {
          uint32 r1 = PARSE_R1;
          uint32 r2 = PARSE_R2;
          uint32 r3 = (w & 0xF8000000) >> 27;

          cmd.Op1.type = cmd.Op2.type = cmd.Op3.type = o_reg;
          cmd.Op1.dtyp = cmd.Op2.dtyp = cmd.Op3.dtyp = dt_dword;
          cmd.Op1.reg  = r1;
          cmd.Op2.reg  = r2;
          cmd.Op3.reg  = r3;
          break;
        }

        //
        // Group match
        //
        if ( op == 0x340 )
          cmd.itype = NEC850_BSW;
        else if ( op == 0x342 )
          cmd.itype = NEC850_BSH;
        else if ( op == 0x344 )
          cmd.itype = NEC850_HSW;
        // process the match
        if ( cmd.itype != 0 )
        {
          uint32 r2 = PARSE_R2;
          uint32 r3 = (w & 0xF8000000) >> 27;
          cmd.Op1.type = cmd.Op2.type = o_reg;
          cmd.Op1.dtyp = cmd.Op2.dtyp = dt_dword;
          cmd.Op1.reg  = r2;
          cmd.Op2.reg  = r3;
          break;
        }

        //
        // match CMOV
        //
        op = w >> 16;
        op = ((op & 0x7E0) >> 4) | (op & 0x1);
        if ( op == 0x30 || op == 0x32 )
        {
          static const int cond_insts[] =
          {
            NEC850_CMOVV,   NEC850_CMOVL,
            NEC850_CMOVZ,   NEC850_CMOVNH,
            NEC850_CMOVN,   NEC850_CMOV,
            NEC850_CMOVLT,  NEC850_CMOVLE,
            NEC850_CMOVNV,  NEC850_CMOVNC,
            NEC850_CMOVNZ,  NEC850_CMOVH,
            NEC850_CMOVP,   NEC850_CMOVSA,
            NEC850_CMOVGE,  NEC850_CMOVGT
          };
          uint32 cc = (w & 0x1E0000) >> 17;
          cmd.itype = cond_insts[cc];

          uint32 r1 = PARSE_R1;
          uint32 r2 = PARSE_R2;
          uint32 r3 = (w & 0xF8000000) >> 27;

          if ( op == 0x32 ) // CMOV reg1, reg2, reg3
          {
            cmd.Op1.type = o_reg;
            cmd.Op1.dtyp = dt_dword;
            cmd.Op1.reg  = r1;
          }
          else
          {
            sval_t v = r1;
            SIGN_EXTEND(sval_t, v, 5);
            cmd.Op1.type       = o_imm;
            cmd.Op1.dtyp       = dt_byte;
            cmd.Op1.value      = v;
            cmd.Op1.specflag1 |= N850F_OUTSIGNED;
          }
          cmd.Op2.type = cmd.Op3.type = o_reg;
          cmd.Op2.dtyp = cmd.Op3.dtyp = dt_dword;
          cmd.Op2.reg  = r2;
          cmd.Op3.reg  = r3;
          break;
        }
        //
        // match MUL[U]_i9
        //
        op = w >> 16;
        op = ((op & 0x7C0) >> 4) | (op & 0x3);
        if ( op == 0x24 || op == 0x26 )
        {
          sval_t imm = (((w & 0x3C0000) >> 18) << 5) | (w & 0x1F);
          if ( op == 0x24 )
          {
            cmd.itype = NEC850_MUL;
            SIGN_EXTEND(sval_t, imm, 9);
            cmd.Op1.specflag1 |= N850F_OUTSIGNED;
          }
          else
            cmd.itype = NEC850_MULU;

          cmd.Op1.value = imm;
          cmd.Op1.dtyp  = dt_word;
          cmd.Op1.type  = o_imm;

          cmd.Op2.type = cmd.Op3.type = o_reg;
          cmd.Op2.dtyp = cmd.Op3.dtyp = dt_dword;
          cmd.Op2.reg  = PARSE_R2;
          cmd.Op3.reg  = (w & 0xF8000000) >> 27;
          break;
        }
      }

      //
      // Format IX
      //
      op = w >> 16; // take 2nd half-word as the opcode
      uint32 reg1 = PARSE_R1;
      uint32 reg2 = PARSE_R2;
      // SETF
      if ( op == 0 )
      {
        static const int cond_insts[] =
        {
          NEC850_SETFV,   NEC850_SETFL,
          NEC850_SETFZ,   NEC850_SETFNH,
          NEC850_SETFN,   NEC850_SETFT,
          NEC850_SETFLT,  NEC850_SETFLE,
          NEC850_SETFNV,  NEC850_SETFNC,
          NEC850_SETFNZ,  NEC850_SETFH,
          NEC850_SETFP,   NEC850_SETFSA,
          NEC850_SETFGE,  NEC850_SETFGT
        };
        cmd.itype = cond_insts[w & 0xF];
        cmd.Op1.type = o_reg;
        cmd.Op1.dtyp = dt_dword;
        cmd.Op1.reg  = reg2;
        break;
      }

      switch ( op )
      {
      case 0x20: // LDSR
        cmd.itype = NEC850_LDSR;
        cmd.Op2.reg = rEIPC; // designate system register
        break;
      case 0x40: // STSR
        cmd.itype = NEC850_STSR;
        cmd.Op1.reg = rEIPC; // designate system register
        break;
      case 0x80: // SHR
        cmd.itype = NEC850_SHR;
        break;
      case 0xA0: // SAR
        cmd.itype = NEC850_SAR;
        break;
      case 0xC0: // SHL
        cmd.itype = NEC850_SHL;
        break;
      }

      if ( cmd.itype != 0 )
      {
        // Common stuff for the rest of Format 9 instructions
        cmd.Op1.dtyp  = cmd.Op2.dtyp = dt_dword;
        cmd.Op1.type  = cmd.Op2.type = o_reg;
        cmd.Op1.reg  += reg1;
        cmd.Op2.reg  += reg2;
        break;
      }

      // No match? Try V850E
      if ( cmd.itype == 0 && is_v850e )
      {
        // SASF
        if ( op == 0x200 )
        {
          static const int cond_insts[] =
          {
            NEC850_SASFV,   NEC850_SASFL,
            NEC850_SASFZ,   NEC850_SASFNH,
            NEC850_SASFN,   NEC850_SASFT,
            NEC850_SASFLT,  NEC850_SASFLE,
            NEC850_SASFNV,  NEC850_SASFNC,
            NEC850_SASFNZ,  NEC850_SASFH,
            NEC850_SASFP,   NEC850_SASFSA,
            NEC850_SASFGE,  NEC850_SASFGT
          };
          cmd.itype = cond_insts[w & 0xF];
          cmd.Op1.type = o_reg;
          cmd.Op1.dtyp = dt_dword;
          cmd.Op1.reg  = reg2;
          break;
        }

        switch ( op )
        {
        case 0xE0: // NOT1
          cmd.itype = NEC850_SET1;
          break;
        case 0xE2: // NOT1
          cmd.itype = NEC850_NOT1;
          break;
        case 0xE4: // CLR1
          cmd.itype = NEC850_CLR1;
          break;
        case 0xE6: // TST1
          cmd.itype = NEC850_TST1;
          break;
        default:
          return 0; // No match!
        }
        // Common
        cmd.Op1.dtyp = dt_byte;
        cmd.Op1.type = o_reg;
        cmd.Op1.reg  = reg2;

        cmd.Op2.dtyp = dt_byte;
        displ_op     = &cmd.Op2;
        cmd.Op2.type = o_displ;
        cmd.Op2.addr = 0;
        cmd.Op2.reg  = reg1;
        cmd.Op2.specflag1 = N850F_USEBRACKETS;
      }

      if ( cmd.itype == 0 )
        return 0; // unknown instruction

      break;
    }

    //
    // Format V
    //
    op = (w & 0x780) >> 6; // Take bit6->bit10
    // JARL and JR
    if ( op == 0x1E )
    {
      uint32 reg  = PARSE_R2;
      sval_t addr = (((w & 0x3F) << 15) | ((w & 0xFFFE0000) >> 17)) << 1;
      SIGN_EXTEND(sval_t, addr, 22);

      cmd.Op1.addr = cmd.ip + addr;
      cmd.Op1.type = o_near;
      cmd.auxpref  = N850F_ADDR_OP1;
      // per the docs, if reg is zero then JARL turns to JR
      if ( reg == 0 )
      {
        cmd.itype = NEC850_JR;
      }
      else
      {
        cmd.itype    = NEC850_JARL;
        cmd.auxpref |= N850F_CALL;
        cmd.Op2.type = o_reg;
        cmd.Op2.reg  = reg;
        cmd.Op2.dtyp = dt_dword;
      }
      break;
    }

    //
    // Format III
    //
    op = (w & 0x780) >> 7; // Take bit7->bit10
    // Bcond disp9
    if ( op == 0xB )
    {
      static const int inst_3[] =
      {
        NEC850_BV,   NEC850_BL,
        NEC850_BZ,   NEC850_BNH,
        NEC850_BN,   NEC850_BR,
        NEC850_BLT,  NEC850_BLE,
        NEC850_BNV,  NEC850_BNC,
        NEC850_BNZ,  NEC850_BH,
        NEC850_BP,   NEC850_BSA,
        NEC850_BGE,  NEC850_BGT
      };
      sval_t dest = ( ((w & 0x70) >> 4) | ((w & 0xF800) >> 8) ) << 1;
      SIGN_EXTEND(sval_t, dest, 9);

      cmd.itype     = inst_3[w & 0xF];
      cmd.Op1.dtyp  = dt_word;
      cmd.Op1.type  = o_near;
      cmd.Op1.addr  = ea_t(dest + cmd.ip);
      cmd.auxpref   = N850F_ADDR_OP1;
      break;
    }
    //
    // Format IV
    //
    else if ( op >= 6 && op <= 0x10 )
    {
      uint32 reg2 = PARSE_R2;
      uint32 addr = (w & 0x7F); // zero extended
      int idx_d(-1), idx_r(-1);
      char dtyp_d(-1);

      // SLD.B
      if ( op == 6 )
      {
        cmd.itype = NEC850_SLD_B;
        idx_d = 0;
        idx_r = 1;
        dtyp_d = dt_byte;
      }
      // SLD.H
      else if ( op == 8 )
      {
        cmd.itype = NEC850_SLD_H;
        idx_d = 0;
        idx_r = 1;
        dtyp_d = dt_word;
        addr <<= 1;
      }
      // SLD.W
      else if ( op == 10 && ((w & 1) == 0) )
      {
        cmd.itype = NEC850_SLD_W;
        idx_d = 0;
        idx_r = 1;
        dtyp_d = dt_dword;
        addr <<= 1;
      }
      // SST.B
      else if ( op == 7 )
      {
        cmd.itype = NEC850_SST_B;
        idx_d = 1;
        idx_r = 0;
        dtyp_d = dt_byte;
      }
      // SST.H
      else if ( op == 9 )
      {
        cmd.itype = NEC850_SST_H;
        idx_d = 1;
        idx_r = 0;
        dtyp_d = dt_byte;
        // bit0 is already cleared, so the 7bit addr we read
        // can be shifted by one to transform it to 8bit
        addr <<= 1;
      }
      // SST.W
      else if ( op == 10 && ((w & 1) == 1) )
      {
        cmd.itype = NEC850_SST_W;
        idx_d = 1;
        idx_r = 0;
        dtyp_d = dt_dword;
        // clear lower bit because it is set, and shift by one
        // bit 15             0
        //     rrrrr1010dddddd1
        addr = (addr & ~1) << 1;
      }
      else if ( idx_d == -1 || idx_r == -1 || dtyp_d == - 1 )
        return false; // could not decode

      cmd.Operands[idx_r].type      = o_reg;
      cmd.Operands[idx_r].reg       = reg2;
      cmd.Operands[idx_r].dtyp      = dt_dword;

      cmd.Operands[idx_d].type      = o_displ;
      displ_op                      = &cmd.Operands[idx_d];
      cmd.Operands[idx_d].reg       = rEP;
      cmd.Operands[idx_d].addr      = addr;
      cmd.Operands[idx_d].dtyp      = dtyp_d;
      cmd.Operands[idx_d].specflag1 = N850F_USEBRACKETS;
      break;
    }
    // Unknown instructions
    cmd.itype = NEC850_NULL;
  } while ( false );

  // special cases when we have memory access through displacement
  if ( displ_op != NULL )
  {
    // A displacement with GP and GP is set?
    if ( displ_op->reg == rGP && g_gp_ea != BADADDR )
    {
      displ_op->type  = o_mem;
      displ_op->addr += g_gp_ea;
    }
    // register zero access?
    else if ( displ_op->reg == rZERO )
    {
      // since r0 is always 0, we can replace the operand by the complete address
      displ_op->type = o_mem;
      displ_op->specflag1 &= ~N850F_OUTSIGNED;
    }
  }

  return cmd.itype != 0;
}

//------------------------------------------------------------------------
// Analyze one instruction and fill 'cmd' structure.
// cmd.ea contains address of instruction to analyze.
// Return length of the instruction in bytes, 0 if instruction can't be decoded.
// This function shouldn't change the database, flags or anything else.
// All these actions should be performed only by u_emu() function.
int idaapi nec850_ana(void)
{
  uint32 w;
  if ( cmd.ea & 0x1 )
    return 0;

  fetch_instruction(&w);
  if ( decode_instruction(w, ::cmd) )
    return cmd.size;
  else
    return 0;
}
