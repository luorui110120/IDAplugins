/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su, ig@datarescue.com
 *                              FIDO:   2:5020/209
 *
 */

#include "i51.hpp"

static int ana_basic(void);
static int ana_extended(void);
//----------------------------------------------------------------------
inline uint32 get_next_24bits()
{
  uint32 high = ua_next_byte();
  uint32 low  = ua_next_word();
  return low | (high<<16);
}

//----------------------------------------------------------------------
static void operand1(int nibble)
{
  switch ( nibble )
  {
    case 4:
      cmd.Op1.type = o_reg;
      cmd.Op1.reg = rAcc;
      break;
    case 5:
      cmd.Op1.type = o_mem;
      cmd.Op1.addr = ua_next_byte();
      break;
    case 6:
      cmd.Op1.type = o_phrase;
      cmd.Op1.phrase = fR0;
      break;
    case 7:
      cmd.Op1.type = o_phrase;
      cmd.Op1.phrase = fR1;
      break;
    default:
      cmd.Op1.type = o_reg;
      cmd.Op1.phrase = uint16(rR0 + (nibble-8));
      break;
  }
}

//----------------------------------------------------------------------
static void operand2(ushort nibble)
{
  switch ( nibble )
  {
    case 4:
      cmd.Op2.type = o_imm;
      cmd.Op2.value = ua_next_byte();
      break;
    case 5:
      cmd.Op2.type = o_mem;
      cmd.Op2.addr = ua_next_byte();
      break;
    case 6:
      cmd.Op2.type = o_phrase;
      cmd.Op2.phrase = fR0;
      break;
    case 7:
      cmd.Op2.type = o_phrase;
      cmd.Op2.phrase = fR1;
      break;
    default:
      cmd.Op2.type = o_reg;
      cmd.Op2.phrase = rR0 + (nibble-8);
      break;
  }
}

//----------------------------------------------------------------------
inline void opAcc(op_t &op)
{
  op.type = o_reg;
  op.reg = rAcc;
}

//----------------------------------------------------------------------
inline void opC(op_t &op)
{
  op.type = o_reg;
  op.reg = rC;
}

//----------------------------------------------------------------------
inline void opAcc(void)
{
  cmd.Op1.type = o_reg;
  cmd.Op1.reg = rAcc;
}

//----------------------------------------------------------------------
// register direct
static int op_rd(op_t &x, uint16 reg, uchar dtyp)
{
  if ( reg >= rDR32 && reg <= rDR52 ) return 0;
  x.type = o_reg;
  x.dtyp = dtyp;
  x.reg  = reg;
  return 1;
}

//----------------------------------------------------------------------
// register indirect
static int op_ph(op_t &x, int reg, uchar dtyp)
{
  if ( reg >= rDR32 && reg <= rDR52 ) return 0;
  x.type = o_phrase;
  x.dtyp = dtyp;
  x.reg  = fRi;
  x.indreg = uchar(reg);
  return 1;
}

//----------------------------------------------------------------------
// register indirect with displacement
static int op_ds(op_t &x, uint16 phrase, uval_t disp, uchar dtyp)
{
  if ( phrase >= rDR32 && phrase <= rDR52 ) return 0;
  x.type = o_displ;
  x.dtyp = dtyp;
  x.phrase = phrase;
  x.addr = disp;
  return 1;
}

//----------------------------------------------------------------------
inline void op_mm(op_t &x, uval_t addr, uchar dtyp)
{
  x.type = o_mem;
  x.dtyp = dtyp;
  x.addr = addr;
}

//----------------------------------------------------------------------
inline void op_near(op_t &x, uval_t addr)
{
  x.type = o_near;
  x.dtyp = dt_word;
  x.addr = addr;
}

//----------------------------------------------------------------------
inline void op_im(op_t &x, uval_t value, uchar dtyp)
{
  x.type  = o_imm;
  x.dtyp  = dtyp;
  x.value = value;
}

//----------------------------------------------------------------------
static uint32 truncate(uval_t addr)
{
  if ( ptype == prc_51 )
    return addr & 0xFFFF;
  else
    return addr & 0xFFFFFF;
}

//----------------------------------------------------------------------
static int make_short(uint16 itype, uchar b)
{
  cmd.itype = itype;
  static const uchar bregs[] = { rR0, rWR0, 0, rDR0 };
  static const uchar dtyps[] = { dt_byte, dt_word, dt_dword };
  int idx = (b >> 2) & 3;
  if ( !op_rd(cmd.Op1, bregs[idx] + (b>>4), dtyps[idx]) ) return 0;
  b &= 3;
  if ( b == 3 ) return 0;
  op_im(cmd.Op2, 1<<b, dt_byte);
  return cmd.size;
}

//----------------------------------------------------------------------
// analyze extended instruction set

static int ana_extended(void)
{
  int code = ua_next_byte();
  if ( (code & 8) == 0 ) return 0;
  if ( (code & 0xF0) >= 0xE0 ) return 0;

static uchar itypes[] =
{
/*      8         9          A          B         C         D         E         F  */
/* 0 */ I51_jsle, I51_mov  , I51_movz , I51_mov , I51_null, I51_null, I51_sra , I51_null,
/* 1 */ I51_jsg , I51_mov  , I51_movs , I51_mov , I51_null, I51_null, I51_srl , I51_null,
/* 2 */ I51_jle , I51_mov  , I51_null , I51_null, I51_add , I51_add , I51_add , I51_add ,
/* 3 */ I51_jg  , I51_mov  , I51_null , I51_null, I51_null, I51_null, I51_sll , I51_null,
/* 4 */ I51_jsl , I51_mov  , I51_null , I51_null, I51_orl , I51_orl , I51_orl , I51_null,
/* 5 */ I51_jsge, I51_mov  , I51_null , I51_null, I51_anl , I51_anl , I51_anl , I51_null,
/* 6 */ I51_je  , I51_mov  , I51_null , I51_null, I51_xrl , I51_xrl , I51_xrl , I51_null,
/* 7 */ I51_jne , I51_mov  , I51_mov  , I51_null, I51_mov , I51_mov , I51_mov , I51_mov ,
/* 8 */ I51_null, I51_ljmp , I51_ejmp , I51_null, I51_div , I51_div , I51_null, I51_null,
/* 9 */ I51_null, I51_lcall, I51_ecall, I51_null, I51_sub , I51_sub , I51_sub , I51_sub ,
/* A */ I51_null, I51_last , I51_eret , I51_null, I51_mul , I51_mul , I51_null, I51_null,
/* B */ I51_null, I51_trap , I51_null , I51_null, I51_cmp , I51_cmp , I51_cmp , I51_cmp ,
/* C */ I51_null, I51_null , I51_push , I51_null, I51_null, I51_null, I51_null, I51_null,
/* D */ I51_null, I51_null , I51_pop  , I51_null, I51_null, I51_null, I51_null, I51_null,
};
  cmd.itype = itypes[ ((code&0xF0)>>1) | (code & 7) ];
  if ( cmd.itype == I51_null ) return 0;

  uchar b1, b2;
  int oax = 0;
  switch ( code )
  {
    case 0x08:          // rel
    case 0x18:
    case 0x28:
    case 0x38:
    case 0x48:
    case 0x58:
    case 0x68:
    case 0x78:
      {
        cmd.Op1.type = o_near;
        cmd.Op1.dtyp = dt_word;
        signed char off = ua_next_byte();
        cmd.Op1.addr = truncate(cmd.ip + cmd.size + off); // signed addition
      }
      break;

    case 0x09:          // mov Rm, @WRj+dis
      b1 = ua_next_byte();
      op_rd(cmd.Op1, rR0 +(b1>>4), dt_byte);
      cmd.Op2.offb = (uchar)cmd.size;
      op_ds(cmd.Op2, rWR0+(b1&15), ua_next_word(), dt_byte);
      break;

    case 0x49:          // mov WRk, @WRj+dis
      b1 = ua_next_byte();
      op_rd(cmd.Op1, rWR0+(b1>>4), dt_word);
      cmd.Op2.offb = (uchar)cmd.size;
      op_ds(cmd.Op2, rWR0+(b1&15), ua_next_word(), dt_word);
      break;

    case 0x29:          // mov Rm, @DRj+dis
      b1 = ua_next_byte();
      op_rd(cmd.Op1, rR0 +(b1>>4), dt_byte);
      cmd.Op2.offb = (uchar)cmd.size;
      if ( !op_ds(cmd.Op2, rDR0+(b1&15), ua_next_word(), dt_byte) ) return 0;
      break;

    case 0x69:          // mov WRj, @DRk+dis
      b1 = ua_next_byte();
      op_rd(cmd.Op1, rWR0+(b1>>4), dt_word);
      cmd.Op2.offb = (uchar)cmd.size;
      if ( !op_ds(cmd.Op2, rDR0+(b1&15), ua_next_word(), dt_word) ) return 0;
      break;

    case 0x19:          // mov @WRj+dis, Rm
      b1 = ua_next_byte();
      cmd.Op1.offb = (uchar)cmd.size;
      op_ds(cmd.Op1, rWR0+(b1&15), ua_next_word(), dt_byte);
      op_rd(cmd.Op2, rR0 +(b1>>4), dt_byte);
      break;

    case 0x59:          // mov @WRj+dis, WRk
      b1 = ua_next_byte();
      cmd.Op1.offb = (uchar)cmd.size;
      op_ds(cmd.Op1, rWR0+(b1&15), ua_next_word(), dt_word);
      op_rd(cmd.Op2, rWR0+(b1>>4), dt_word);
      break;

    case 0x39:          // mov @DRj+dis, Rm
      b1 = ua_next_byte();
      cmd.Op1.offb = (uchar)cmd.size;
      if ( !op_ds(cmd.Op1, rDR0+(b1&15), ua_next_word(), dt_byte) ) return 0;
      op_rd(cmd.Op2, rR0 +(b1>>4), dt_byte);
      break;

    case 0x79:          // mov @DRk+dis, WRj
      b1 = ua_next_byte();
      cmd.Op1.offb = (uchar)cmd.size;
      if ( !op_ds(cmd.Op1, rDR0+(b1&15), ua_next_word(), dt_word) ) return 0;
      op_rd(cmd.Op2, rWR0+(b1>>4), dt_word);
      break;

    case 0x0A:          // movz WRj, Rm
    case 0x1A:          // movs WRj, Rm
      b1 = ua_next_byte();
      op_rd(cmd.Op1, rWR0+(b1>>4), dt_word);
      op_rd(cmd.Op2, rR0 +(b1&15), dt_byte);
      break;

    case 0x0B:          // 1000 mov WRj, @WRj
                        // 1010 mov WRj, @DRk
      {
        b1 = ua_next_byte();
        int ri;
        switch ( b1 & 15 )
        {
          case 0x8: ri = rWR0; break;
          case 0xA: ri = rDR0; break;
          case 0x9: return 0;
          case 0xB: return 0;
          default:  return make_short(I51_inc, b1);
        }
        b2 = ua_next_byte();
        if ( b2 & 15 ) return 0;
        op_rd(cmd.Op1, rWR0+(b2>>4), dt_word);
        if ( !op_ph(cmd.Op2, ri  +(b1>>4), dt_word) ) return 0;
      }
      break;

    case 0x1B:          // 1000 mov @WRj, WRj
                        // 1010 mov @DRk, WRj
      {
        b1 = ua_next_byte();
        int ri;
        switch ( b1 & 15 )
        {
          case 0x8: ri = rWR0; break;
          case 0xA: ri = rDR0; break;
          case 0x9: return 0;
          case 0xB: return 0;
          default:  return make_short(I51_dec, b1);
        }
        b2 = ua_next_byte();
        if ( b2 & 15 ) return 0;
        if ( !op_ph(cmd.Op1, ri  +(b1>>4), dt_word) ) return 0;
        op_rd(cmd.Op2, rWR0+(b2>>4), dt_word);
      }
      break;

    case 0x7A:
      {
        b1 = ua_next_byte();
        switch ( b1&15 )
        {
          case 9:                 // 1001 mov @WRj, Rm
          case 0xB:               // 1011 mov @DRk, Rm
            b2 = ua_next_byte();
            if ( b2 & 15 ) return 0;
            if ( !op_ph(cmd.Op1, ((b1&2) ? rDR0 : rWR0) + (b1>>4), dt_byte) )
              return 0;
            op_rd(cmd.Op2, rR0+(b2>>4), dt_byte);
            break;
          case 0xC:               // movh DRk, #data16
            cmd.itype = I51_movh;
            if ( !op_rd(cmd.Op1, rDR0+(b1>>4), dt_dword) ) return 0;
            cmd.Op2.offb = (uchar)cmd.size;
            op_im(cmd.Op2, ua_next_word(), dt_word);
            break;
          default:
            goto CONT;
        }
        break;
CONT:
        uval_t addr = (b1&2) ? ua_next_word() : ua_next_byte();
        switch ( b1&15 )
        {
          case 0x1:               // mov dir8, Rm
          case 0x3:               // mov dir16, Rm
            op_mm(cmd.Op1, addr, dt_byte);
            op_rd(cmd.Op2, rR0+(b1>>4), dt_byte);
            break;
          case 0x5:               // mov dir8, WRj
          case 0x7:               // mov dir16, WRj
            op_mm(cmd.Op1, addr, dt_word);
            op_rd(cmd.Op2, rWR0+(b1>>4), dt_word);
            break;
          case 0xD:               // mov dir8, DRj
          case 0xF:               // mov dir16, DRj
            op_mm(cmd.Op1, addr, dt_dword);
            if ( !op_rd(cmd.Op2, rDR0+(b1>>4), dt_dword) ) return 0;
            break;
          default: return 0;
        }
      }
      break;

    case 0x89:          // ljmp  @WRj or @DRj
    case 0x99:          // lcall @WRj or @DRj
      {
        int r;
        uchar dt;
        b1 = ua_next_byte();
        switch ( b1 & 15 )
        {
          case 4:
            r = rWR0;
            dt = dt_word;
            break;
          case 8:
            r = rDR0;
            dt = dt_dword;
            cmd.itype = (cmd.itype==I51_ljmp) ? I51_ejmp : I51_ecall;
            break;
          default:
            return 0;
        }
        if ( !op_ph(cmd.Op1, r+(b1>>4), dt) ) return 0;
      }
      break;

    case 0x8A:          // ejmp  addr24
    case 0x9A:          // ecall addr24
      op_near(cmd.Op1, get_next_24bits());
      break;

    case 0xAA:          // eret
    case 0xB9:          // trap
      break;

    case 0xCA:          // push
    case 0xDA:          // pop
      b1 = ua_next_byte();
      switch ( b1 & 15 )
      {
        case 0x1:                                       // mov DRk, PC
          if ( code != 0xCA ) return 0;
          cmd.itype = I51_mov;
          if ( !op_rd(cmd.Op1, rDR0+(b1>>4), dt_dword) ) return 0;
          op_rd(cmd.Op2, rPC, dt_dword);
          break;
        case 0x2:                                       // #data8
          cmd.Op1.offb = (uchar)cmd.size;
          op_im(cmd.Op1, ua_next_byte(), dt_byte);
          break;
        case 0x6:                                       // #data16
          cmd.Op1.offb = (uchar)cmd.size;
          op_im(cmd.Op1, ua_next_word(), dt_word);
          break;
        case 0x8:                                       // Rm
          op_rd(cmd.Op1, rR0+(b1>>4), dt_byte);
          break;
        case 0x9:                                       // WRj
          op_rd(cmd.Op1, rWR0+(b1>>4), dt_word);
          break;
        case 0xB:                                       // DRj
          if ( !op_rd(cmd.Op1, rDR0+(b1>>4), dt_dword) ) return 0;
          break;
        default:
          return 0;
      }
      break;

    case 0xA9:          // bit instructions
      {
        static const uchar itypes[] =
        {
          I51_null, I51_jbc,  I51_jb,   I51_jnb,
          I51_null, I51_null, I51_null, I51_orl,
          I51_anl,  I51_mov,  I51_mov,  I51_cpl,
          I51_clr,  I51_setb, I51_orl,  I51_anl
        };
        b1 = ua_next_byte();
        if ( b1 & 8 ) return 0;
        cmd.itype = itypes[ b1 >> 4];
        if ( cmd.itype == I51_null ) return 0;
        cmd.Op1.type = o_bit251;
        cmd.Op1.dtyp = dt_byte;
        cmd.Op1.b251_bit = b1 & 7;
        cmd.Op1.addr = ua_next_byte();
        cmd.Op1.b251_bitneg = 0;
        switch ( b1 >> 4 )
        {
          case 0x1:             // jbc bit, rel
          case 0x2:             // jb  bit, rel
          case 0x3:             // jnb bit, rel
            {
              signed char rel = ua_next_byte();
              op_near(cmd.Op2, truncate(cmd.ip + cmd.size + rel));
            }
            break;
          case 0xE:             // orl cy, /bit
          case 0xF:             // anl cy, /bit
            cmd.Op1.b251_bitneg = 1;
            /* no break */
          case 0x7:             // orl cy, bit
          case 0x8:             // anl cy, bit
          case 0xA:             // mov cy, bit
            cmd.Op2 = cmd.Op1;
            opC(cmd.Op1);
            break;
          case 0x9:             // mov bit, cy
            opC(cmd.Op2);
            break;
          case 0xB:             // cpl  bit
          case 0xC:             // clr  bit
          case 0xD:             // setb bit
            break;
        }
      }
      break;

    case 0x0E:          // sra
    case 0x1E:          // srl
    case 0x3E:          // sll
      b1 = ua_next_byte();
      switch ( b1 & 15 )
      {
        case 0:
          op_rd(cmd.Op1, rR0 +(b1>>4), dt_byte);
          break;
        case 4:
          op_rd(cmd.Op1, rWR0+(b1>>4), dt_word);
          break;
        default:
          return 0;
      }
      break;

    case 0x2C:          // add Rm, Rm
    case 0x4C:          // orl Rm, Rm
    case 0x5C:          // anl Rm, Rm
    case 0x6C:          // xrl Rm, Rm
    case 0x7C:          // mov Rm, Rm
    case 0x8C:          // div Rm, Rm
    case 0x9C:          // sub Rm, Rm
    case 0xAC:          // mul Rm, Rm
    case 0xBC:          // cmp Rm, Rm
      b1 = ua_next_byte();
      op_rd(cmd.Op1, rR0+(b1>>4), dt_byte);
      op_rd(cmd.Op2, rR0+(b1&15), dt_byte);
      break;

    case 0x2D:          // add WRj, WRj
    case 0x4D:          // orl WRj, WRj
    case 0x5D:          // anl WRj, WRj
    case 0x6D:          // xrl WRj, WRj
    case 0x7D:          // mov WRj, WRj
    case 0x8D:          // div WRj, WRj
    case 0x9D:          // sub WRj, WRj
    case 0xAD:          // mul WRj, WRj
    case 0xBD:          // cmp WRj, WRj
      b1 = ua_next_byte();
      op_rd(cmd.Op1, rWR0+(b1>>4), dt_word);
      op_rd(cmd.Op2, rWR0+(b1&15), dt_word);
      break;

    case 0x2F:          // add DRj, DRj
    case 0x7F:          // mov DRj, DRj
    case 0x9F:          // sub DRj, DRj
    case 0xBF:          // cmp DRj, DRj
      b1 = ua_next_byte();
      if ( !op_rd(cmd.Op1, rDR0+(b1>>4), dt_dword) ) return 0;
      if ( !op_rd(cmd.Op2, rDR0+(b1&15), dt_dword) ) return 0;
      break;

    case 0x4E:          // orl reg, op2
    case 0x5E:          // anl reg, op2
    case 0x6E:          // xrl reg, op2
      oax = 1;  // orl, anl, xrl
      /* no break */
    case 0x2E:          // add reg, op2
    case 0x7E:          // mov reg, op2
    case 0x8E:          // div reg, op2
    case 0x9E:          // sub reg, op2
    case 0xAE:          // mul reg, op2
    case 0xBE:          // cmp reg, op2
      b1 = ua_next_byte();
      switch ( b1 & 15 )
      {
        case 0x0:                                       // Rm, #8
          op_rd(cmd.Op1, rR0+(b1>>4), dt_byte);
          cmd.Op2.offb = (uchar)cmd.size;
          op_im(cmd.Op2, ua_next_byte(), dt_byte);
          break;
        case 0x4:                                       // WRj, #16
          op_rd(cmd.Op1, rWR0+(b1>>4), dt_word);
          cmd.Op2.offb = (uchar)cmd.size;
          op_im(cmd.Op2, ua_next_word(), dt_word);
          break;
        case 0x8:                                       // DRk, #16
          if ( oax ) return 0;
          if ( !op_rd(cmd.Op1, rDR0+(b1>>4), dt_dword) ) return 0;
          cmd.Op2.offb = (uchar)cmd.size;
          op_im(cmd.Op2, ua_next_word(), dt_word);
          break;
        case 0xC:                                       // DRk, #(1)16
          if ( oax ) return 0;
          if ( !op_rd(cmd.Op1, rDR0+(b1>>4), dt_dword) ) return 0;
          cmd.Op2.offb = (uchar)cmd.size;
          op_im(cmd.Op2, ua_next_word(), dt_word);
          cmd.auxpref |= aux_1ext;
          break;
        case 0x1:                                       // Rm, dir8
          op_rd(cmd.Op1, rR0+(b1>>4), dt_byte);
          op_mm(cmd.Op2, ua_next_byte(), dt_byte);
          break;
        case 0x5:                                       // WRj, dir8
          op_rd(cmd.Op1, rWR0+(b1>>4), dt_word);
          op_mm(cmd.Op2, ua_next_byte(), dt_word);
          break;
        case 0xD:                                       // DRk, dir8
          if ( oax ) return 0;
          if ( !op_rd(cmd.Op1, rDR0+(b1>>4), dt_dword) ) return 0;
          op_mm(cmd.Op2, ua_next_byte(), dt_word);
          break;
        case 0x3:                                       // Rm, dir16
          op_rd(cmd.Op1, rR0+(b1>>4), dt_byte);
          op_mm(cmd.Op2, ua_next_word(), dt_byte);
          break;
        case 0x7:                                       // WRj, dir16
          op_rd(cmd.Op1, rWR0+(b1>>4), dt_word);
          op_mm(cmd.Op2, ua_next_word(), dt_word);
          break;
        case 0xF:                                       // DRk, dir16
          if ( code != 0x7E ) return 0;         // only mov works
          if ( !op_rd(cmd.Op1, rDR0+(b1>>4), dt_dword) ) return 0;
          op_mm(cmd.Op2, ua_next_word(), dt_word);
          break;
        case 0x9:                                       // Rm, @WRj
          b2 = ua_next_byte();
          if ( b2 & 15 ) return 0;
          op_rd(cmd.Op1, rR0 +(b2>>4), dt_byte);
          op_ph(cmd.Op2, rWR0+(b1>>4), dt_byte);
          break;
        case 0xB:                                       // Rm, @DRk
          b2 = ua_next_byte();
          if ( b2 & 15 ) return 0;
          op_rd(cmd.Op1, rR0 +(b2>>4), dt_byte);
          if ( !op_ph(cmd.Op2, rDR0+(b1>>4), dt_byte) ) return 0;
          break;
        default:
          return 0;
      }
      break;

    default:
      error("%a: internal ana_extended() error, code=%x", cmd.ea, code);
  }

  return cmd.size;
}

//----------------------------------------------------------------------
// analyze an basic instruction
static int ana_basic(void)
{

  ushort code = ua_next_byte();

  ushort nibble0 = (code & 0xF);
  ushort nibble1 = (code >> 4);
  char off;
  if ( nibble0 < 4 )              // complex coding, misc instructions
  {
    switch ( nibble0 )
    {
      case 0:
        {
          static const uchar misc0[16] =
          {
            I51_nop, I51_jbc, I51_jb,  I51_jnb,
            I51_jc,  I51_jnc, I51_jz,  I51_jnz,
            I51_sjmp,I51_mov, I51_orl, I51_anl,
            I51_push,I51_pop, I51_movx,I51_movx
          };
          cmd.itype = misc0[nibble1];
        }
        switch ( nibble1 )
        {
          case 0x1: case 0x2: case 0x3:
            cmd.Op1.type  = o_bit;
            cmd.Op1.reg = ua_next_byte();
            cmd.Op2.type = o_near;
            off = ua_next_byte();
            cmd.Op2.addr = truncate(cmd.ip + cmd.size + off); // signed addition
            cmd.Op2.dtyp = dt_word;
            break;
          case 0x4: case 0x5: case 0x6: case 0x7: case 0x8:
            cmd.Op1.type = o_near;
            off = ua_next_byte();
            cmd.Op1.addr = truncate(cmd.ip + cmd.size + off); // signed addition
            cmd.Op1.dtyp = dt_word;
            break;
          case 0x9:
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = rDptr;
            cmd.Op1.dtyp = dt_word;
            cmd.Op2.type  = o_imm;
            cmd.Op2.offb  = (uchar)cmd.size;
            cmd.Op2.value = ua_next_word();
            cmd.Op2.dtyp = dt_word;
            break;
          case 0xA:
          case 0xB:
            opC(cmd.Op1);
            cmd.Op2.type = o_bitnot;
            cmd.Op2.reg = ua_next_byte();
            break;
          case 0xC:
          case 0xD:
            cmd.Op1.type = o_mem;
            cmd.Op1.addr = ua_next_byte();
            break;
          case 0xE:
            opAcc(cmd.Op1);
            cmd.Op2.type = o_phrase;
            cmd.Op2.phrase = fDptr;
            break;
          case 0xF:
            opAcc(cmd.Op2);
            cmd.Op1.type = o_phrase;
            cmd.Op1.phrase = fDptr;
            break;
        }
        break;
      case 1:
        {
          ushort lowbits = ua_next_byte();
          cmd.Op1.type = o_near;
          cmd.Op1.addr = truncate((code&0xE0)<<3) + lowbits + ((cmd.ip+cmd.size) & ~0x7FF);
          cmd.Op1.dtyp = dt_word;
          cmd.itype = (nibble1 & 1) ? I51_acall : I51_ajmp;
        }
        break;
      case 2:
        {
          static const uchar misc2[16] =
          {
            I51_ljmp,I51_lcall,I51_ret,I51_reti,
            I51_orl, I51_anl, I51_xrl, I51_orl,
            I51_anl, I51_mov, I51_mov, I51_cpl,
            I51_clr, I51_setb,I51_movx,I51_movx
          };
          cmd.itype = misc2[nibble1];
        }
        switch ( nibble1 ) {
          case 0x0: case 0x1:
            cmd.Op1.type = o_near;
            cmd.Op1.addr = ua_next_word();
            cmd.Op1.addr|= (cmd.ip+cmd.size) & ~0xFFFF;
            cmd.Op1.dtyp = dt_word;
            break;
          case 0x4: case 0x5: case 0x6:
            cmd.Op1.type = o_mem;
            cmd.Op1.addr = ua_next_byte();
            opAcc(cmd.Op2);
            break;
          case 0x7: case 0x8: case 0xA:
            opC(cmd.Op1);
            cmd.Op2.type = o_bit;
            cmd.Op2.reg = ua_next_byte();
            break;
          case 0x9:
            opC(cmd.Op2);
            /* no break */
          case 0xB: case 0xC: case 0xD:
            cmd.Op1.type = o_bit;
            cmd.Op1.reg = ua_next_byte();
            break;
          case 0xE:
            opAcc();
            cmd.Op2.type = o_phrase;
            cmd.Op2.phrase = fR0;
            break;
          case 0xF:
            cmd.Op1.type = o_phrase;
            cmd.Op1.phrase = fR0;
            opAcc(cmd.Op2);
            break;
        }
        break;
      case 3:
        {
          static const uchar misc3[16] =
          {
            I51_rr,  I51_rrc, I51_rl,  I51_rlc,
            I51_orl, I51_anl, I51_xrl, I51_jmp,
            I51_movc,I51_movc,I51_inc, I51_cpl,
            I51_clr, I51_setb,I51_movx,I51_movx
          };
          cmd.itype = misc3[nibble1];
        }
        switch ( nibble1 ) {
          case 0x0: case 0x1: case 0x2: case 0x3:
            opAcc();
            break;
          case 0x4: case 0x5: case 0x6:
            cmd.Op1.type = o_mem;
            cmd.Op1.addr = ua_next_byte();
            cmd.Op2.offb  = (uchar)cmd.size;
            cmd.Op2.type  = o_imm;
            cmd.Op2.value = ua_next_byte();
            break;
          case 0x7:
            cmd.Op1.type = o_phrase;
            cmd.Op1.phrase = fAdptr;
            break;
          case 0x8:
            opAcc();
            cmd.Op2.type = o_phrase;
            cmd.Op2.phrase = fApc;
            break;
          case 0x9:
            opAcc();
            cmd.Op2.type = o_phrase;
            cmd.Op2.phrase = fAdptr;
            break;
          case 0xA:
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = rDptr;
            cmd.Op1.dtyp = dt_word;
            break;
          case 0xB:
          case 0xC:
          case 0xD:
            opC(cmd.Op1);
            break;
          case 0xE:
            opAcc();
            cmd.Op2.type = o_phrase;
            cmd.Op2.phrase = fR1;
            break;
          case 0xF:
            cmd.Op1.type = o_phrase;
            cmd.Op1.phrase = fR1;
            opAcc(cmd.Op2);
            break;
        }
        break;
    }
  } else {         // i.e. nibble0 >= 4
    static const uchar regulars[16] =
    {
      I51_inc, I51_dec, I51_add, I51_addc,
      I51_orl, I51_anl, I51_xrl, I51_mov,
      I51_mov, I51_subb,I51_mov, I51_cjne,
      I51_xch, I51_djnz,I51_mov, I51_mov
    };
    cmd.itype = regulars[nibble1];
    switch ( nibble1 ) {
      case 0x00:                // inc
      case 0x01:                // dec
        operand1(nibble0);
        break;
      case 0x0C:                // xch
        if ( nibble0 == 4 ) {
          cmd.itype = I51_swap;
          opAcc();
          break;
        }
      case 0x02:                // add
      case 0x03:                // addc
      case 0x04:                // orl
      case 0x05:                // anl
      case 0x06:                // xrl
      case 0x09:                // subb
        operand2(nibble0);
        opAcc();
        break;
      case 0x07:                // mov
        operand1(nibble0);
        cmd.Op2.offb = (uchar)cmd.size;
        cmd.Op2.type = o_imm;
        cmd.Op2.value = ua_next_byte();
        break;
      case 0x08:                // mov
        if ( nibble0 == 4 ) {
          cmd.itype = I51_div;
          cmd.Op1.type = o_reg;
          cmd.Op1.reg = rAB;
          break;
        }
        operand2(nibble0);
        cmd.Op1.type = o_mem;
        cmd.Op1.addr = ua_next_byte();
        break;
      case 0x0A:                // mov
        if ( nibble0 == 4 ) {
          cmd.itype = I51_mul;
          cmd.Op1.type = o_reg;
          cmd.Op1.reg = rAB;
          break;
        }
        if ( nibble0 == 5 ) return 0;   // mov to imm - no sense (0xA5)
        operand1(nibble0);
        cmd.Op2.type = o_mem;
        cmd.Op2.addr = ua_next_byte();
        break;
      case 0x0B:                // cjne
        if ( nibble0 == 5 ) {
          opAcc();
          cmd.Op2.type = o_mem;
          cmd.Op2.addr = ua_next_byte();
        } else {
          operand1(nibble0);
          cmd.Op2.offb  = (uchar)cmd.size;
          cmd.Op2.type = o_imm;
          cmd.Op2.value = ua_next_byte();
        }
        cmd.Op3.type = o_near;
        off = ua_next_byte();
        cmd.Op3.addr = truncate(cmd.ip + cmd.size + off);  // signed addition
        cmd.Op3.dtyp = dt_word;
        break;
      case 0x0D:                // djnz
        switch ( nibble0 ) {
          case 4:
            cmd.itype = I51_da;
            opAcc();
            break;
          case 6:
          case 7:
            cmd.itype = I51_xchd;
            opAcc();
            operand2(nibble0);
            break;
          default:
            operand1(nibble0);
            off = ua_next_byte();
            cmd.Op2.type = o_near;
            cmd.Op2.addr = truncate(cmd.ip + cmd.size + off); // signed addition
            cmd.Op2.dtyp = dt_word;
            break;
        }
        break;
      case 0x0E:                // mov
        opAcc();
        if ( nibble0 == 4 ) {
          cmd.itype = I51_clr;
          break;
        }
        operand2(nibble0);
        break;
      case 0x0F:                // mov
        if ( nibble0 == 4 ) {
          cmd.itype = I51_cpl;
          opAcc();
          break;
        }
        operand1(nibble0);
        cmd.Op2.type = o_reg;
        cmd.Op2.reg = rAcc;
        break;
    }
  }
  return cmd.size;
}

//----------------------------------------------------------------------
// analyze an instruction
int idaapi ana(void)
{
  cmd.Op1.dtyp = dt_byte;
  cmd.Op2.dtyp = dt_byte;
  cmd.Op3.dtyp = dt_byte;

  uchar code = get_byte(cmd.ea);
  switch ( ptype )
  {
    case prc_51:
      return ana_basic();

    case prc_251_src:
    case prc_930_src:
      if ( code == 0xA5 )
      {
        cmd.size++;             // skip A5
        code = get_byte(cmd.ea+1);
        if ( (code & 15) < 6 ) return 0;
        return ana_basic();
      }
      if ( (code & 15) < 6 ) return ana_basic();
      return ana_extended();

    case prc_251_bin:
    case prc_930_bin:
      if ( code == 0xA5 )
      {
        cmd.size++;             // skip A5
        return ana_extended();
      }
      return ana_basic();
  }
  return 0;
}
