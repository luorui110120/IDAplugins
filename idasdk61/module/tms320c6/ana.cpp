/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su
 *                              FIDO:   2:5020/209
 *
 *
 *      TMS320C6xx - VLIW (very long instruction word) architecture
 *
 */

 // SWAP4 is not disassembled!

#include "tms6.hpp"

//--------------------------------------------------------------------------
struct tmsinsn_t
{
  uchar itype;
  uchar src1;
  uchar src2;
  uchar dst;
};

// operand types
#define t_none           0
#define t_sint           1
#define t_xsint          2
#define t_uint           3
#define t_xuint          4
#define t_slong          5
#define t_xslong         6
#define t_ulong          7
#define t_xulong         8
#define t_scst5          9
#define t_ucst5         10
#define t_slsb16        11
#define t_xslsb16       12
#define t_ulsb16        13
#define t_xulsb16       14
#define t_smsb16        15
#define t_xsmsb16       16
#define t_umsb16        17
#define t_xumsb16       18
#define t_irp           19
#define t_cregr         20
#define t_cregw         21
#define t_ucst1         22
#define t_dp            23
#define t_xdp           24
#define t_sp            25
#define t_xsp           26
#define t_ucst15        27
#define t_scst7         28
#define t_ucst3         29
#define t_b14           30
#define t_dint          31
#define t_i2            32
#define t_xi2           33
#define t_i4            34
#define t_xi4           35
#define t_s2            36
#define t_xs2           37
#define t_u2            38
#define t_xu2           39
#define t_s4            40
#define t_xs4           41
#define t_u4            42
#define t_xu4           43
#define t_scst10        44
#define t_scst12        45
#define t_scst21        46
#define t_a3            47      // a3 or b3
#define t_bv2           48      // 2 bits
#define t_bv4           49      // 4 bits
#define t_ds2           50
#define t_sllong        51
#define t_ullong        52
#define t_dws4          53
#define t_dwu4          54

static uint32 g_code;
//--------------------------------------------------------------------------
static void swap_op1_and_op2(void)
{
  if ( (cmd.cflags & aux_pseudo) == 0 )
  {
    op_t tmp = cmd.Op1;
    cmd.Op1 = cmd.Op2;
    cmd.Op2 = tmp;
    cmd.Op1.n = 0;
    cmd.Op2.n = 1;
  }
}

//--------------------------------------------------------------------------
static void swap_op2_and_op3(void)
{
  if ( (cmd.cflags & aux_pseudo) == 0 )
  {
    op_t tmp = cmd.Op3;
    cmd.Op3 = cmd.Op2;
    cmd.Op2 = tmp;
    cmd.Op2.n = 1;
    cmd.Op3.n = 2;
  }
}

//--------------------------------------------------------------------------
inline int op_spmask(op_t &x, uint32 code)
{
  x.type = o_spmask;
  x.dtyp = dt_dword;
  x.reg = (code >> 18) & 0xFF;
  return cmd.size;
}

//--------------------------------------------------------------------------
inline void op_reg(op_t &x, int reg)
{
  x.type = o_reg;
  x.dtyp = dt_dword;
  x.reg = reg;
}

//--------------------------------------------------------------------------
inline void op_ucst15(op_t &x, uint32 code)
{
  x.type = o_imm;
  x.dtyp = dt_dword;
  x.value = (code >> 8) & 0x7FFF;
}

//--------------------------------------------------------------------------
inline bool second_unit(void)
{
  return cmd.funit == FU_L2
      || cmd.funit == FU_S2
      || cmd.funit == FU_M2
      || cmd.funit == FU_D2;
}

//--------------------------------------------------------------------------
static uchar make_reg(int32 v, bool isother)
{
  if ( second_unit() == isother )
    return uchar(v);
  else
    return uchar((v) + rB0);
}

//--------------------------------------------------------------------------
// bcb __ea64__ fails with backend error if this function is declared inline
static void op_near(op_t &x, int shift, uval_t mask)
{
  x.type = o_near;
  x.dtyp = dt_code;
  sval_t cst = (g_code >> shift) & mask;
  int signbit = (mask + 1) >> 1;
  if ( cst & signbit )
    cst |= ~mask;     // extend sign
  cst <<= 2;
  x.addr = (cmd.ip & ~0x1F) + cst;
}

//--------------------------------------------------------------------------
struct tms_reginfo_t
{
  int mask;
  int idx;
  int reg;
};

static const tms_reginfo_t ctrls[] =
{
  { 0x21F, 0x00, rAMR    }, // Addressing mode register
  { 0x21F, 0x01, rCSR    }, // Control status register
//  { 0x21F, 0x02, rIFR    }, // Interrupt flag register
  { 0x21F, 0x02, rISR    }, // Interrupt set register
  { 0x21F, 0x03, rICR    }, // Interrupt clear register
  { 0x21F, 0x04, rIER    }, // Interrupt enable register
  { 0x21F, 0x05, rISTP   }, // Interrupt service table pointer register
  { 0x21F, 0x06, rIRP    }, // Interrupt return pointer register
  { 0x21F, 0x07, rNRP    }, // Nonmaskable interrupt or exception return pointer
  { 0x3FF, 0x0A, rTSCL   }, // Time-stamp counter (low 32 bits) register
  { 0x3FF, 0x0B, rTSCH   }, // Time-stamp counter (high 32 bits) register
  { 0x3FF, 0x0D, rILC    }, // Inner loop count register
  { 0x3FF, 0x0E, rRILC   }, // Reload inner loop count register
  { 0x3FF, 0x0F, rREP    }, // Restricted entry point address register
  { 0x3FF, 0x10, rPCE1   }, // Program counter, E1 phase
  { 0x3FF, 0x11, rDNUM   }, // DSP core number register
  { 0x3FF, 0x12, rFADCR  }, // Floating-point adder configuration register
  { 0x3FF, 0x13, rFAUCR  }, // Floating-point auxiliary configuration register
  { 0x3FF, 0x14, rFMCR   }, // Floating-point multiplier configuration register
  { 0x3FF, 0x15, rSSR    }, // Saturation status register
  { 0x3FF, 0x16, rGPLYA  }, // GMPY A-side polynomial register
  { 0x3FF, 0x17, rGPLYB  }, // GMPY B-side polynomial register
  { 0x3FF, 0x18, rGFPGFR }, // Galois field multiply control register
  { 0x3FF, 0x1A, rTSR    }, // Task state register
  { 0x3FF, 0x1B, rITSR   }, // Interrupt task state register
  { 0x3FF, 0x1C, rNTSR   }, // NMI/Exception task state register
  { 0x3FF, 0x1D, rECR    }, // Exception clear register
//  { 0x3FF, 0x1D, rEFR    }, // Exception flag register
  { 0x3FF, 0x1F, rIERR   }, // Internal exception report register
};

static int find_crreg(int idx)
{
  for ( int i=0; i < qnumber(ctrls); i++ )
    if ( ctrls[i].idx == (idx & ctrls[i].mask) )
      return ctrls[i].reg;
  return -1;
}

//--------------------------------------------------------------------------
static int make_op(op_t &x, uchar optype, int32 v, bool isother)
{
  switch ( optype )
  {
    case t_none:
      break;
    case t_s2:
    case t_u2:
    case t_i2:
    case t_i4:
    case t_s4:
    case t_u4:
    case t_ds2:
    case t_sint:
    case t_uint:
    case t_bv2:
    case t_bv4:
      isother = false;
      // no break
    case t_xs2:
    case t_xu2:
    case t_xi2:
    case t_xi4:
    case t_xu4:
    case t_xs4:
    case t_xsint:
    case t_xuint:
      x.type = o_reg;
      x.dtyp = dt_dword;
      x.reg = make_reg(v, isother);
      break;
    case t_slsb16:
    case t_ulsb16:
    case t_smsb16:
    case t_umsb16:
      isother = false;
      // no break
    case t_xslsb16:
    case t_xulsb16:
    case t_xsmsb16:
    case t_xumsb16:
      x.type = o_reg;
      x.dtyp = dt_word;
      x.reg = make_reg(v, isother);
      break;
    case t_dint:
    case t_slong:
    case t_ulong:
    case t_sllong:
    case t_ullong:
    case t_dws4:
    case t_dwu4:
      isother = false;
      // no break
    case t_xslong:
    case t_xulong:
      x.type = o_regpair;
      x.dtyp = dt_qword;
      x.reg = make_reg(v, isother);
      break;
    case t_sp:
      isother = false;
      // no break
    case t_xsp:
      x.type = o_reg;
      x.dtyp = dt_float;
      x.reg = make_reg(v, isother);
      break;
    case t_dp:
      isother = false;
      // no break
    case t_xdp:
      x.type = o_regpair;
      x.dtyp = dt_double;
      x.reg = make_reg(v & ~1, isother);
      break;
    case t_ucst1:
      if ( v != 0 && v != 1 )
        return 0;
      /* fall thru */
    case t_scst5:
      if ( v & 0x10 )
        v |= ~0x1FL;              // extend sign
      /* fall thru */
    case t_ucst5:
      x.type = o_imm;
      x.dtyp = dt_dword;
      x.value = v;
      break;
    case t_ucst15:
      x.type = o_imm;
      x.dtyp = dt_dword;
      x.value = (g_code >> 8) & 0x7FFF;
      break;
    case t_ucst3:
      x.type = o_imm;
      x.dtyp = dt_dword;
      x.value = (g_code >> 13) & 7;
      break;
    case t_scst7:
      op_near(x, 16, 0x7F);
      break;
    case t_scst10:
      op_near(x, 13, 0x3FF);
      break;
    case t_scst12:
      op_near(x, 16, 0xFFF);
      break;
    case t_scst21:
      op_near(x, 7, 0x1FFFFF);
      break;
    case t_irp:
      x.type = o_reg;
      x.dtyp = dt_word;
           if ( v == 6 ) x.reg = rIRP;
      else if ( v == 7 ) x.reg = rNRP;
      else return 0;
      break;
    case t_cregr: // read control reg
      {
        int idx = ((g_code >> 18) & 0x1F) | ((g_code >> (13-5)) & 0x3E0);
        int reg = find_crreg(idx);
        if ( reg == -1 )
          return 0;
        if ( reg == rISR )
          reg = rIFR;
        if ( reg == rECR )
          reg = rEFR;
        op_reg(x, reg);
      }
      break;
    case t_cregw:
      {
        int idx = ((g_code >> 23) & 0x1F) | ((g_code >> (13-5)) & 0x3E0);
        int reg = find_crreg(idx);
        if ( reg == -1 )
          return 0;
        op_reg(x, reg);
      }
      break;
    case t_b14:
      op_reg(x, rB14 + ((g_code>>7)&1));
      break;
    case t_a3:
      op_reg(x, make_reg(rA3, isother));
      break;
    default:
      INTERR(257);
  }
  return true;
}

//--------------------------------------------------------------------------
static void make_pseudo(void)
{
  switch ( cmd.itype )
  {
    case TMS6_add:
    case TMS6_or:
      if ( cmd.Op1.type == o_imm && cmd.Op1.value == 0 )
      {
        cmd.itype = TMS6_mv;
SHIFT_OPS:
        cmd.Op1 = cmd.Op2;
        cmd.Op2 = cmd.Op3;
        cmd.Op1.n = 0;
        cmd.Op2.n = 1;
        cmd.Op3.type = o_void;
        cmd.cflags |= aux_pseudo;
      }
      break;
    case TMS6_sub:
      if ( cmd.Op1.type == o_imm
        && cmd.Op1.value == 0
        && cmd.funit != FU_D1
        && cmd.funit != FU_D2 )
      {
        cmd.itype = TMS6_neg;
        goto SHIFT_OPS;
      }
      if ( cmd.Op1.type == o_reg
        && cmd.Op2.type == o_reg
        && cmd.Op3.type == o_reg
        && cmd.Op1.reg  == cmd.Op2.reg )
      {
        cmd.itype = TMS6_zero;
        cmd.Op1.reg = cmd.Op3.reg;
        cmd.Op2.type = o_void;
        cmd.Op3.type = o_void;
        cmd.cflags |= aux_pseudo;
      }
      break;
    case TMS6_xor:
      if ( cmd.Op1.type == o_imm && cmd.Op1.value == uval_t(-1) )
      {
        cmd.itype = TMS6_not;
        goto SHIFT_OPS;
      }
      break;
    case TMS6_packlh2:
      if ( cmd.Op1.type == o_reg
        && cmd.Op2.type == o_reg
        && cmd.Op1.reg  == cmd.Op2.reg )
      {
        cmd.itype = TMS6_swap2;
        swap_op2_and_op3();
        cmd.Op3.type = o_void;
        cmd.cflags |= aux_pseudo;
      }
      break;
  }
}

//--------------------------------------------------------------------------
static int table_insns(uint32 code, const tmsinsn_t *insn, bool isother)
{
// +------------------------------------------...
// |31    29|28|27    23|22   18|17        13|...
// |  creg  |z |  dst   |  src2 |  src1/cst  |...
// +------------------------------------------...

  if ( insn->itype == TMS6_null )
    return 0;
  cmd.itype = insn->itype;
  if ( isother )
    cmd.cflags |= aux_xp;  // xpath is used
  g_code = code;
  op_t *xptr = &cmd.Op1;
  if ( !make_op(*xptr, insn->src1, (code >> 13) & 0x1F, isother) ) return 0;
  if ( xptr->type != o_void ) xptr++;
  if ( !make_op(*xptr, insn->src2, (code >> 18) & 0x1F, isother) ) return 0;
  if ( xptr->type != o_void ) xptr++;
  if ( !make_op(*xptr, insn->dst,  (code >> 23) & 0x1F, isother) ) return 0;
  make_pseudo();
  return cmd.size;
}

//--------------------------------------------------------------------------
//      L UNIT OPERATIONS
//--------------------------------------------------------------------------
static const tmsinsn_t lops[128] =
{                                                                // bits 11..5
  { TMS6_pack2,  t_i2,          t_xi2,          t_i2            }, // 000 0000
  { TMS6_dptrunc,t_none,        t_dp,           t_sint          }, // 000 0001
  { TMS6_add,    t_scst5,       t_xsint,        t_sint          }, // 000 0010
  { TMS6_add,    t_sint,        t_xsint,        t_sint          }, // 000 0011
  { TMS6_sub2,   t_i2,          t_xi2,          t_i2            }, // 000 0100
  { TMS6_add2,   t_i2,          t_xi2,          t_i2            }, // 000 0101
  { TMS6_sub,    t_scst5,       t_xsint,        t_sint          }, // 000 0110
  { TMS6_sub,    t_sint,        t_xsint,        t_sint          }, // 000 0111
  { TMS6_dpint,  t_none,        t_dp,           t_sint          }, // 000 1000
  { TMS6_dpsp,   t_none,        t_dp,           t_sp            }, // 000 1001
  { TMS6_spint,  t_none,        t_sp,           t_sint          }, // 000 1010
  { TMS6_sptrunc,t_none,        t_xsp,          t_sint          }, // 000 1011
  { TMS6_null,   t_none,        t_none,         t_none          }, // 000 1100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 000 1101
  { TMS6_ssub,   t_scst5,       t_xsint,        t_sint          }, // 000 1110
  { TMS6_ssub,   t_sint,        t_xsint,        t_sint          }, // 000 1111
  { TMS6_addsp,  t_sp,          t_xsp,          t_sp            }, // 001 0000
  { TMS6_subsp,  t_sp,          t_xsp,          t_sp            }, // 001 0001
  { TMS6_sadd,   t_scst5,       t_xsint,        t_sint          }, // 001 0010
  { TMS6_sadd,   t_sint,        t_xsint,        t_sint          }, // 001 0011
  { TMS6_null,   t_none,        t_none,         t_none          }, // 001 0100
  { TMS6_subsp,  t_xsp,         t_sp,           t_sp            }, // 001 0101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 001 0110
  { TMS6_sub,    t_xsint,       t_sint,         t_sint          }, // 001 0111
  { TMS6_adddp,  t_dp,          t_xdp,          t_dp            }, // 001 1000
  { TMS6_subdp,  t_dp,          t_xdp,          t_dp            }, // 001 1001
  { -1,          t_none,        t_xsint,        t_sint          }, // 001 1010 *
  { TMS6_packlh2,t_i2,          t_xi2,          t_i2            }, // 001 1011 *
  { TMS6_packhl2,t_i2,          t_xi2,          t_i2            }, // 001 1100
  { TMS6_subdp,  t_xdp,         t_dp,           t_dp            }, // 001 1101
  { TMS6_packh2, t_i2,          t_xi2,          t_i2            }, // 001 1110
  { TMS6_ssub,   t_xsint,       t_sint,         t_sint          }, // 001 1111
  { TMS6_add,    t_scst5,       t_slong,        t_slong         }, // 010 0000
  { TMS6_add,    t_xsint,       t_slong,        t_slong         }, // 010 0001
  { TMS6_null,   t_none,        t_none,         t_none          }, // 010 0010
  { TMS6_add,    t_sint,        t_xsint,        t_slong         }, // 010 0011
  { TMS6_sub,    t_scst5,       t_slong,        t_slong         }, // 010 0100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 010 0101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 010 0110
  { TMS6_sub,    t_sint,        t_xsint,        t_slong         }, // 010 0111
  { TMS6_null,   t_none,        t_none,         t_none          }, // 010 1000
  { TMS6_addu,   t_xuint,       t_ulong,        t_ulong         }, // 010 1001
  { TMS6_null,   t_none,        t_none,         t_none          }, // 010 1010
  { TMS6_addu,   t_uint,        t_xuint,        t_ulong         }, // 010 1011
  { TMS6_ssub,   t_scst5,       t_slong,        t_slong         }, // 010 1100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 010 1101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 010 1110
  { TMS6_subu,   t_uint,        t_xuint,        t_ulong         }, // 010 1111
  { TMS6_sadd,   t_scst5,       t_slong,        t_slong         }, // 011 0000
  { TMS6_sadd,   t_xsint,       t_slong,        t_slong         }, // 011 0001
  { TMS6_null,   t_none,        t_none,         t_none          }, // 011 0010
  { TMS6_null,   t_none,        t_none,         t_none          }, // 011 0011
  { TMS6_null,   t_none,        t_none,         t_none          }, // 011 0100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 011 0101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 011 0110
  { TMS6_sub,    t_xsint,       t_sint,         t_slong         }, // 011 0111
  { TMS6_abs,    t_none,        t_slong,        t_slong         }, // 011 1000
  { TMS6_intdp,  t_none,        t_xsint,        t_dp            }, // 011 1001
  { TMS6_null,   t_none,        t_none,         t_none          }, // 011 1010
  { TMS6_intdpu, t_none,        t_xuint,        t_dp            }, // 011 1011
  { TMS6_null,   t_none,        t_none,         t_none          }, // 011 1100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 011 1101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 011 1110
  { TMS6_subu,   t_xuint,       t_uint,         t_ulong         }, // 011 1111
  { TMS6_sat,    t_none,        t_slong,        t_sint          }, // 100 0000
  { TMS6_min2,   t_s2,          t_xs2,          t_s2            }, // 100 0001
  { TMS6_max2,   t_s2,          t_xs2,          t_s2            }, // 100 0010
  { TMS6_maxu4,  t_u4,          t_xu4,          t_u4            }, // 100 0011
  { TMS6_cmpgt,  t_scst5,       t_slong,        t_uint          }, // 100 0100
  { TMS6_cmpgt,  t_xsint,       t_slong,        t_uint          }, // 100 0101
  { TMS6_cmpgt,  t_scst5,       t_xsint,        t_uint          }, // 100 0110
  { TMS6_cmpgt,  t_sint,        t_xsint,        t_uint          }, // 100 0111
  { TMS6_minu4,  t_u4,          t_xu4,          t_u4            }, // 100 1000
  { TMS6_intspu, t_none,        t_xuint,        t_sp            }, // 100 1010
  { TMS6_intsp,  t_none,        t_xsint,        t_sp            }, // 100 1010
  { TMS6_subc,   t_uint,        t_xuint,        t_uint          }, // 100 1011
  { TMS6_cmpgtu, t_scst5,       t_ulong,        t_uint          }, // 100 1100
  { TMS6_cmpgtu, t_xuint,       t_ulong,        t_uint          }, // 100 1101
  { TMS6_cmpgtu, t_scst5,       t_xuint,        t_uint          }, // 100 1110
  { TMS6_cmpgtu, t_uint,        t_xuint,        t_uint          }, // 100 1111
  { TMS6_cmpeq,  t_scst5,       t_slong,        t_uint          }, // 101 0000
  { TMS6_cmpeq,  t_xsint,       t_slong,        t_uint          }, // 101 0001
  { TMS6_cmpeq,  t_scst5,       t_xsint,        t_uint          }, // 101 0010
  { TMS6_cmpeq,  t_sint,        t_xsint,        t_uint          }, // 101 0011
  { TMS6_cmplt,  t_scst5,       t_slong,        t_uint          }, // 101 0100
  { TMS6_cmplt,  t_xsint,       t_slong,        t_uint          }, // 101 0101
  { TMS6_cmplt,  t_scst5,       t_xsint,        t_uint          }, // 101 0110
  { TMS6_cmplt,  t_sint,        t_xsint,        t_uint          }, // 101 0111
  { TMS6_null,   t_none,        t_none,         t_none          }, // 101 1000
  { TMS6_null,   t_none,        t_none,         t_none          }, // 101 1001
  { TMS6_subabs4,t_u4,          t_xu4,          t_u4            }, // 101 1010
  { TMS6_null,   t_none,        t_none,         t_none          }, // 101 1011
  { TMS6_cmpltu, t_scst5,       t_ulong,        t_uint          }, // 101 1100
  { TMS6_cmpltu, t_xuint,       t_ulong,        t_uint          }, // 101 1101
  { TMS6_cmpltu, t_scst5,       t_xuint,        t_uint          }, // 101 1110
  { TMS6_cmpltu, t_uint,        t_xuint,        t_uint          }, // 101 1111
  { TMS6_norm,   t_none,        t_slong,        t_uint          }, // 110 0000
  { TMS6_shlmb,  t_u4,          t_xu4,          t_u4            }, // 110 0001
  { TMS6_shrmb,  t_u4,          t_xu4,          t_u4            }, // 110 0010
  { TMS6_norm,   t_none,        t_xsint,        t_uint          }, // 110 0011
  { TMS6_ssub2,  t_s2,          t_xs2,          t_s2            }, // 110 0100
  { TMS6_add4,   t_i4,          t_xi4,          t_i4            }, // 110 0101
  { TMS6_sub4,   t_i4,          t_xi4,          t_i4            }, // 110 0101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 110 0111
  { TMS6_packl4, t_i4,          t_xi4,          t_i4            }, // 110 1000
  { TMS6_packh4, t_i4,          t_xi4,          t_i4            }, // 110 1001
  { TMS6_lmbd,   t_ucst1,       t_xuint,        t_uint          }, // 110 1010
  { TMS6_lmbd,   t_uint,        t_xuint,        t_uint          }, // 110 1011
  { TMS6_null,   t_none,        t_none,         t_none          }, // 110 1100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 110 1101
  { TMS6_xor,    t_scst5,       t_xuint,        t_uint          }, // 110 1110
  { TMS6_xor,    t_uint,        t_xuint,        t_uint          }, // 110 1111
  { TMS6_addsp,  t_sp,          t_xsp,          t_sp            }, // 111 0000
  { TMS6_subsp,  t_sp,          t_xsp,          t_sp            }, // 111 0001
  { TMS6_adddp,  t_dp,          t_xdp,          t_dp            }, // 111 0010
  { TMS6_subdp,  t_dp,          t_xdp,          t_dp            }, // 111 0011
  { TMS6_null,   t_none,        t_none,         t_none          }, // 111 0100
  { TMS6_subsp,  t_xsp,         t_sp,           t_sp            }, // 111 0101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 111 0110
  { TMS6_subdp,  t_xdp,         t_dp,           t_dp            }, // 111 0111
  { TMS6_null,   t_none,        t_none,         t_none          }, // 111 1000
  { TMS6_null,   t_none,        t_none,         t_none          }, // 111 1001
  { TMS6_and,    t_scst5,       t_xuint,        t_uint          }, // 111 1010
  { TMS6_and,    t_uint,        t_xuint,        t_uint          }, // 111 1011
  { TMS6_andn,   t_uint,        t_xuint,        t_uint          }, // 111 1100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 111 1101
  { TMS6_or,     t_scst5,       t_xuint,        t_uint          }, // 111 1110
  { TMS6_or,     t_uint,        t_xuint,        t_uint          }, // 111 1111
};

static const tmsinsn_t esc1A[32] =
{
  { TMS6_abs,    t_none,        t_xsint,        t_sint          }, // 0 0000
  { TMS6_swap4,  t_none,        t_xu4,          t_u4            }, // 0 0001
  { TMS6_unpklu4,t_none,        t_xsint,        t_sint          }, // 0 0010
  { TMS6_unpkhu4,t_none,        t_xsint,        t_sint          }, // 0 0011
  { TMS6_abs2,   t_none,        t_xs2,          t_s2            }, // 0 0100
  { TMS6_mvk,    t_none,        t_scst5,        t_sint          }, // 0 0101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 0 0110
  { TMS6_null,   t_none,        t_none,         t_none          }, // 0 0111
  { TMS6_null,   t_none,        t_none,         t_none          }, // 0 1000
  { TMS6_null,   t_none,        t_none,         t_none          }, // 0 1001
  { TMS6_null,   t_none,        t_none,         t_none          }, // 0 1010
  { TMS6_null,   t_none,        t_none,         t_none          }, // 0 1011
  { TMS6_null,   t_none,        t_none,         t_none          }, // 0 1100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 0 1101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 0 1110
  { TMS6_null,   t_none,        t_none,         t_none          }, // 0 1111
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 0000
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 0001
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 0010
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 0011
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 0100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 0101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 0110
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 0111
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 1000
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 1001
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 1010
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 1011
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 1100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 1101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 1110
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 1111
};

static int l_ops(uint32 code)
{
// +--------------------------------------------------------------+
// |31    29|28|27    23|22   18|17        13|12|11    5|4|3|2|1|0|
// |  creg  |z |  dst   |  src2 |  src1/cst  |x |   op  |1|1|0|s|p|
// +--------------------------------------------------------------+

  int opcode = (code >> 5) & 0x7F;
  const tmsinsn_t *table = lops;
  switch ( opcode )
  {
    case 0x1A:
      opcode = (code >> 13) & 0x1F;
      table = esc1A;
      break;
    case 0x70: // addsp
    case 0x71: // subsp
    case 0x72: // adddp
    case 0x73: // subdp
      cmd.funit += 2; // move from L to S unit
      break;
  }
  return table_insns(code, table + opcode, (code & BIT12) != 0);
}

//--------------------------------------------------------------------------
//      M UNIT OPERATIONS
//--------------------------------------------------------------------------
static const tmsinsn_t mops[32] =
{                                                              // bits 11..7
  { TMS6_null,    t_none,       t_none,         t_none          }, // 0 0000
  { TMS6_mpyh,    t_smsb16,     t_xsmsb16,      t_sint          }, // 0 0001
  { TMS6_smpyh,   t_smsb16,     t_xsmsb16,      t_sint          }, // 0 0010
  { TMS6_mpyhsu,  t_smsb16,     t_xumsb16,      t_sint          }, // 0 0011
  { TMS6_mpyi,    t_sint,       t_xsint,        t_sint          }, // 0 0100
  { TMS6_mpyhus,  t_umsb16,     t_xsmsb16,      t_sint          }, // 0 0101
  { TMS6_mpyi,    t_scst5,      t_xsint,        t_sint          }, // 0 0110
  { TMS6_mpyhu,   t_umsb16,     t_xumsb16,      t_uint          }, // 0 0111
  { TMS6_mpyid,   t_sint,       t_xsint,        t_dint          }, // 0 1000
  { TMS6_mpyhl,   t_smsb16,     t_xslsb16,      t_sint          }, // 0 1001
  { TMS6_smpyhl,  t_smsb16,     t_xslsb16,      t_sint          }, // 0 1010
  { TMS6_mpyhslu, t_smsb16,     t_xulsb16,      t_sint          }, // 0 1011
  { TMS6_mpyid,   t_scst5,      t_xsint,        t_dint          }, // 0 1100
  { TMS6_mpyhuls, t_umsb16,     t_xslsb16,      t_sint          }, // 0 1101
  { TMS6_mpydp,   t_dp,         t_dp,           t_dp            }, // 0 1110
  { TMS6_mpyhlu,  t_umsb16,     t_xulsb16,      t_uint          }, // 0 1111
  { TMS6_mpy32,   t_sint,       t_xsint,        t_sint          }, // 1 0000
  { TMS6_mpylh,   t_slsb16,     t_xsmsb16,      t_sint          }, // 1 0001
  { TMS6_smpylh,  t_slsb16,     t_xsmsb16,      t_sint          }, // 1 0010
  { TMS6_mpylshu, t_slsb16,     t_xumsb16,      t_sint          }, // 1 0011
  { TMS6_null,    t_none,       t_none,         t_none          }, // 1 0100
  { TMS6_mpyluhs, t_ulsb16,     t_xsmsb16,      t_sint          }, // 1 0101
  { TMS6_mpy32su, t_sint,       t_xuint,        t_dint          }, // 1 0000
  { TMS6_mpylhu,  t_ulsb16,     t_xumsb16,      t_uint          }, // 1 0111
  { TMS6_mpy,     t_scst5,      t_xslsb16,      t_sint          }, // 1 1000
  { TMS6_mpy,     t_slsb16,     t_xslsb16,      t_sint          }, // 1 1001
  { TMS6_smpy,    t_slsb16,     t_xslsb16,      t_sint          }, // 1 1010
  { TMS6_mpysu,   t_slsb16,     t_xulsb16,      t_sint          }, // 1 1011
  { TMS6_mpysp,   t_sp,         t_xsp,          t_sp            }, // 1 1100
  { TMS6_mpyus,   t_ulsb16,     t_xslsb16,      t_sint          }, // 1 1101
  { TMS6_mpysu,   t_scst5,      t_xulsb16,      t_sint          }, // 1 1110
  { TMS6_mpyu,    t_ulsb16,     t_xulsb16,      t_uint          }, // 1 1111
};

inline int m_ops(uint32 code)
{
// +------------------------------------------------------------------+
// |31    29|28|27    23|22   18|17        13|12|11    7|6|5|4|3|2|1|0|
// |  creg  |z |  dst   |  src2 |  src1/cst  |x |   op  |0|0|0|0|0|s|p|
// +------------------------------------------------------------------+

  return table_insns(code, mops + ((code >> 7) & 0x1F), (code & BIT12) != 0);
}

//--------------------------------------------------------------------------
//      D UNIT OPERATIONS
//--------------------------------------------------------------------------
static tmsinsn_t dops[] =
{                                                               // bits 12..7
  { TMS6_add,   t_sint,         t_sint,         t_sint          }, // 01 0000
  { TMS6_sub,   t_sint,         t_sint,         t_sint          }, // 01 0001
  { TMS6_add,   t_ucst5,        t_sint,         t_sint          }, // 01 0010
  { TMS6_sub,   t_ucst5,        t_sint,         t_sint          }, // 01 0011
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 0100
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 0101
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 0110
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 0111
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 1000
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 1001
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 1010
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 1011
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 1100
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 1101
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 1110
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 1111
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 0000
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 0001
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 0010
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 0011
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 0100
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 0101
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 0110
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 0111
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 1000
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 1001
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 1010
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 1011
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 1100
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 1101
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 1110
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 1111
  { TMS6_addab, t_sint,         t_sint,         t_sint          }, // 11 0000
  { TMS6_subab, t_sint,         t_sint,         t_sint          }, // 11 0001
  { TMS6_addab, t_ucst5,        t_sint,         t_sint          }, // 11 0010
  { TMS6_subab, t_ucst5,        t_sint,         t_sint          }, // 11 0011
  { TMS6_addah, t_sint,         t_sint,         t_sint          }, // 11 0100
  { TMS6_subah, t_sint,         t_sint,         t_sint          }, // 11 0101
  { TMS6_addah, t_ucst5,        t_sint,         t_sint          }, // 11 0110
  { TMS6_subah, t_ucst5,        t_sint,         t_sint          }, // 11 0111
  { TMS6_addaw, t_sint,         t_sint,         t_sint          }, // 11 1000
  { TMS6_subaw, t_sint,         t_sint,         t_sint          }, // 11 1001
  { TMS6_addaw, t_ucst5,        t_sint,         t_sint          }, // 11 1010
  { TMS6_subaw, t_ucst5,        t_sint,         t_sint          }, // 11 1011
  { TMS6_addad, t_sint,         t_sint,         t_sint          }, // 11 1100
  { TMS6_addad, t_ucst5,        t_sint,         t_sint          }, // 11 1101
  { TMS6_null,  t_none,         t_none,         t_none          }, // 11 1110
  { TMS6_null,  t_none,         t_none,         t_none          }, // 11 1111
};

static int d_ops(uint32 code)
{
// +--------------------------------------------------------------+
// |31    29|28|27    23|22   18|17        13|12   7|6|5|4|3|2|1|0|
// |  creg  |z |  dst   |  src2 |  src1/cst  |  op  |1|0|0|0|0|s|p|
// +--------------------------------------------------------------+

  int opcode = (code >> 7) & 0x3F;
  int res = 0;
  if ( opcode == 0 )
  {
    static const tmsinsn_t mvk = { TMS6_mvk, t_scst5, t_none, t_sint };
    res = table_insns(code, &mvk, 0);
  }
  else if ( opcode >= 0x10 )
  {
    res = table_insns(code, dops + (opcode - 0x10), 0);
    if ( res != 0 )
      swap_op1_and_op2();
  }
  return res;
}

//--------------------------------------------------------------------------
//      D UNIT OPERATIONS WITH CROSSPATH
//--------------------------------------------------------------------------
static tmsinsn_t dxops[32] =
{                                                               // bits 11..7
  { TMS6_mpy2,    t_s2,         t_xs2,          t_ullong        }, // 0 0000
  { TMS6_dotpsu4, t_s4,         t_xu4,          t_uint          }, // 0 0001
  { TMS6_mpyu4,   t_u4,         t_xu4,          t_dwu4          }, // 0 0010
  { TMS6_dotpu4,  t_s4,         t_xu4,          t_uint          }, // 0 0011
  { TMS6_null,    t_none,       t_none,         t_none          }, // 0 0100
  { TMS6_null,    t_none,       t_none,         t_none          }, // 0 0101
  { TMS6_dotp2,   t_s2,         t_xs2,          t_sint          }, // 0 0110
  { TMS6_mpylir,  t_sint,       t_xsint,        t_sint          }, // 0 0111
  { TMS6_mpyhir,  t_sint,       t_xsint,        t_sint          }, // 0 1000
  { TMS6_avgu4,   t_u4,         t_xu4,          t_u4            }, // 0 1001
  { TMS6_mpyhi,   t_sint,       t_xsint,        t_sllong        }, // 0 1010
  { TMS6_mpyspdp, t_sp,         t_xsp,          t_sp            }, // 0 1011
  { TMS6_mpy32u,  t_uint,       t_xuint,        t_dint          }, // 0 1100
  { TMS6_sshvr,   t_sint,       t_xsint,        t_sint          }, // 0 1101
  { TMS6_sshvl,   t_sint,       t_xsint,        t_sint          }, // 0 1110
  { TMS6_rotl,    t_ucst5,      t_xuint,        t_uint          }, // 0 1111
  { TMS6_andn,    t_uint,       t_xuint,        t_uint          }, // 1 0000
  { TMS6_or,      t_uint,       t_xuint,        t_uint          }, // 1 0001
  { TMS6_add2,    t_i2,         t_xi2,          t_i2            }, // 1 0010
  { TMS6_and,     t_uint,       t_xuint,        t_uint          }, // 1 0011
  { TMS6_null,    t_none,       t_none,         t_none          }, // 1 0100
  { TMS6_add,     t_sint,       t_xsint,        t_sint          }, // 1 0101
  { TMS6_sub,     t_sint,       t_xsint,        t_sint          }, // 1 0110
  { TMS6_xor,     t_uint,       t_xuint,        t_uint          }, // 1 0111
  { TMS6_sadd2,   t_s2,         t_xs2,          t_s2            }, // 1 1000
  { TMS6_spack2,  t_sint,       t_xsint,        t_s2            }, // 1 1001
  { TMS6_spacku4, t_s2,         t_xs2,          t_u4            }, // 1 1010
  { TMS6_andn,    t_uint,       t_xuint,        t_uint          }, // 1 1011
  { TMS6_shru2,   t_uint,       t_xu2,          t_u2            }, // 1 1011
  { TMS6_shrmb,   t_u4,         t_xu4,          t_u4            }, // 1 1101
  { TMS6_min2,    t_s2,         t_xs2,          t_s2            }, // 1 1110
  { TMS6_null,    t_none,       t_none,         t_none          }, // 1 1111
};

static int handle_dx(const tmsinsn_t *table, uint32 code)
{
  int opcode = (code >> 7) & 0x1F;
  if ( opcode < 0x10 )
    cmd.funit -= 2; // D -> M
  else if ( opcode >= 0x18 )
    cmd.funit -= 4; // D -> S
  int size = table_insns(code, table + opcode, (code & BIT12) != 0);
  if ( size > 0 )
  {
    switch ( cmd.itype )
    {
      case TMS6_rotl:
      case TMS6_sshvl:
      case TMS6_sshvr:
      case TMS6_shru2:
        swap_op1_and_op2();
        break;
    }
  }
  return size;
}

inline int dx_ops(uint32 code)
{
// +-----------------------------------------------------------------+
// |31    29|28|27    23|22   18|17        13|12|11   7|6|5|4|3|2|1|0|
// |  creg  |z |  dst   |  src2 |  src1/cst  |x |  op  |0|1|1|0|0|s|p|
// +-----------------------------------------------------------------+

  return handle_dx(dxops, code);
}

//--------------------------------------------------------------------------
//      D UNIT OPERATIONS WITH CONSTANT CROSSPATH
//--------------------------------------------------------------------------
#define BITGRP uchar(-1)

static const tmsinsn_t dxcops[32] =
{                                                              // bits 11..7
  { TMS6_smpy2,    t_s2,        t_xs2,          t_ullong        }, // 0 0000
  { BITGRP,        t_none,      t_xu4,          t_u4            }, // 0 0001
  { TMS6_mpysu4,   t_s4,        t_xu4,          t_dws4          }, // 0 0010
  { TMS6_dotpnrsu2,t_s2,        t_xu2,          t_sint          }, // 0 0011
  { TMS6_dotpn2,   t_s2,        t_xs2,          t_sint          }, // 0 0100
  { TMS6_dotp2,    t_s2,        t_xs2,          t_sllong        }, // 0 0101
  { TMS6_dotprsu2, t_s2,        t_xu2,          t_sint          }, // 0 0110
  { TMS6_null,     t_none,      t_none,         t_none          }, // 0 0111
  { TMS6_gmpy4,    t_u4,        t_xu4,          t_u4,           }, // 0 1000
  { TMS6_avg2,     t_s2,        t_xs2,          t_s2            }, // 0 1001
  { TMS6_mpyli,    t_sint,      t_xsint,        t_sllong        }, // 0 1010
  { TMS6_mpysp2dp, t_sp,        t_xsp,          t_sp            }, // 0 1011
  { TMS6_mpy32us,  t_uint,      t_xsint,        t_dint          }, // 0 1100
  { TMS6_null,     t_none,      t_none,         t_none          }, // 0 1101
  { TMS6_rotl,     t_uint,      t_xuint,        t_uint          }, // 0 1110
  { TMS6_null,     t_none,      t_none,         t_none          }, // 0 1111
  { TMS6_null,     t_none,      t_none,         t_none          }, // 1 0000
  { TMS6_or,       t_scst5,     t_xuint,        t_uint          }, // 1 0001
  { TMS6_sub2,     t_i2,        t_xi2,          t_i2            }, // 1 0010
  { TMS6_and,      t_scst5,     t_xuint,        t_uint          }, // 1 0011
  { TMS6_null,     t_none,      t_none,         t_none          }, // 1 0100
  { TMS6_add,      t_scst5,     t_xsint,        t_sint          }, // 1 0101
  { TMS6_null,     t_none,      t_none,         t_none          }, // 1 0110
  { TMS6_xor,      t_scst5,     t_xuint,        t_uint          }, // 1 0111
  { TMS6_saddus2,  t_u2,        t_xs2,          t_u2            }, // 1 1000
  { TMS6_saddu4,   t_u4,        t_xu4,          t_u4            }, // 1 1001
  { TMS6_sub,      t_sint,      t_xsint,        t_sint          }, // 1 1010
  { TMS6_shr2,     t_uint,      t_xs2,          t_s2            }, // 1 1011
  { TMS6_shlmb,    t_u4,        t_xu4,          t_u4            }, // 1 1100
  { TMS6_dmv,      t_sint,      t_xsint,        t_dint          }, // 1 1101
  { TMS6_max2,     t_s2,        t_xs2,          t_s2            }, // 1 1110
  { TMS6_pack2,    t_i2,        t_xi2,          t_i2            }, // 1 1111
};

static const uchar bititypes[32] =
{
  TMS6_null,  TMS6_null,  TMS6_null,  TMS6_null,
  TMS6_null,  TMS6_null,  TMS6_null,  TMS6_null,
  TMS6_null,  TMS6_null,  TMS6_null,  TMS6_null,
  TMS6_null,  TMS6_null,  TMS6_null,  TMS6_null,
  TMS6_null,  TMS6_null,  TMS6_null,  TMS6_null,
  TMS6_null,  TMS6_null,  TMS6_null,  TMS6_null,
  TMS6_xpnd4, TMS6_xpnd2, TMS6_mvd,   TMS6_null,
  TMS6_shfl,  TMS6_deal,  TMS6_bitc4, TMS6_bitr,
};

static int dxc_ops(uint32 code)
{
// +-----------------------------------------------------------------+
// |31    29|28|27    23|22   18|17        13|12|11   7|6|5|4|3|2|1|0|
// |  creg  |z |  dst   |  src2 |  src1/cst  |x |  op  |1|1|1|0|0|s|p|
// +-----------------------------------------------------------------+

  int size =  handle_dx(dxcops, code);
  if ( size > 0 )
  {
    switch ( cmd.itype )
    {
      case BITGRP:
        cmd.itype = bititypes[(code >>13) & 0x1F];
        if ( cmd.itype == TMS6_null )
          return 0;
        break;
      case TMS6_shr2:
        swap_op1_and_op2();
        break;
    }
  }
  return size;
}

//--------------------------------------------------------------------------
//      LOAD/STORE WITH 15-BIT OFFSET (ON D2 UNIT)
//--------------------------------------------------------------------------
struct tms_ldinfo_t
{
  uchar itype;
  uchar dtype;
  uchar shift;
};

static const tms_ldinfo_t ldinfo[] =
{
  { TMS6_ldhu,  dt_word,  1 },  // 0000
  { TMS6_ldbu,  dt_byte,  0 },  // 0001
  { TMS6_ldb,   dt_byte,  0 },  // 0010
  { TMS6_stb,   dt_byte,  0 },  // 0011
  { TMS6_ldh,   dt_word,  1 },  // 0100
  { TMS6_sth,   dt_word,  1 },  // 0101
  { TMS6_ldw,   dt_dword, 2 },  // 0110
  { TMS6_stw,   dt_dword, 2 },  // 0111
  { TMS6_null,  0,        0 },  // 1000
  { TMS6_null,  0,        0 },  // 1001
  { TMS6_ldndw, dt_qword, 3 },  // 1010
  { TMS6_ldnw,  dt_dword, 2 },  // 1011
  { TMS6_stdw,  dt_qword, 3 },  // 1100
  { TMS6_stnw,  dt_dword, 2 },  // 1101
  { TMS6_lddw,  dt_qword, 3 },  // 1110
  { TMS6_stndw, dt_qword, 3 },  // 1111
};

static int ld_common(uint32 code, bool use_bit8)
{
  int idx = (code >> 4) & 7;
  if ( use_bit8 )
    idx |= (code & BIT8) >> 5;
  const tms_ldinfo_t *ld = &ldinfo[idx];
  cmd.itype = ld->itype;
  if ( cmd.itype == TMS6_null )
    return -1;
  cmd.Op2.type = o_reg;
  cmd.Op2.dtyp = dt_dword;
  cmd.Op2.reg  = (code >> 23) & 0x1F;
  if ( code & BIT1 )
    cmd.Op2.reg += rB0;
  cmd.Op1.dtyp = ld->dtype;
  if ( ld->shift == 3 )
  {
    cmd.Op2.reg &= ~1;
    cmd.Op2.type = o_regpair;
    if ( (code & BIT23) == 0 )
      if ( cmd.itype == TMS6_ldndw || cmd.itype == TMS6_stndw )
        return 1; // no scaling
  }
  return ld->shift;
}

static bool is_store_insn(ushort itype)
{
  switch ( itype )
  {
    case TMS6_stb:
    case TMS6_sth:
    case TMS6_stw:
    case TMS6_stdw:
    case TMS6_stnw:
    case TMS6_stndw:
      return true;
    default:
      return false;
  }
}

static int ld15(uint32 code)
{
  int shift = ld_common(code, false);
  if ( shift == -1 )
    return 0;
  cmd.Op1.type = o_displ;
  cmd.Op1.mode = 5;             // *+R[cst]
  cmd.Op1.reg  = (code & BIT7) ? rB15 : rB14;
  cmd.Op1.addr = (code >> 8) & 0x7FFF;
  bool is_store = is_store_insn(cmd.itype);
  if ( isOff(get_flags_novalue(cmd.ea), is_store) )
    cmd.Op1.addr <<= shift;
  if ( is_store )
    swap_op1_and_op2();
  return cmd.size;
}

//--------------------------------------------------------------------------
//      LOAD/STORE BASER+OFFSETR/CONST (ON D UNITS)
//--------------------------------------------------------------------------
static int ldbase(uint32 code)
{
// +------------------------------------------------------------------------+
// |31    29|28|27   23|22     18|17           13|12   9|8|7|6     4|3|2|1|0|
// |  creg  |z |  dst  |  baseR  | offsetR/ucst5 | mode |r|y| ld/st |0|1|s|p|
// +------------------------------------------------------------------------+

  int shift = ld_common(code, true);
  if ( shift == -1 )
    return 0;
  cmd.Op1.mode = (code >> 9) & 0xF;
  bool is_store = is_store_insn(cmd.itype);
  switch ( cmd.Op1.mode )
  {
    case 0x02:  // 0010
    case 0x03:  // 0011
    case 0x06:  // 0110
    case 0x07:  // 0111
      return 0;
    case 0x00:  // 0000 *-R[cst]
    case 0x01:  // 0001 *+R[cst]
    case 0x08:  // 1000 *--R[cst]
    case 0x09:  // 1001 *++R[cst]
    case 0x0A:  // 1010 *R--[cst]
    case 0x0B:  // 1011 *R++[cst]
      cmd.Op1.type = o_displ;
      cmd.Op1.addr = (code >> 13) & 0x1F;
      if ( isOff(uFlag,is_store) )
        cmd.Op1.addr <<= shift;
      break;
    case 0x04:  // 0100 *-Rb[Ro]
    case 0x05:  // 0101 *+Rb[Ro]
    case 0x0C:  // 1100 *--Rb[Ro]
    case 0x0D:  // 1101 *++Rb[Ro]
    case 0x0E:  // 1110 *Rb--[Ro]
    case 0x0F:  // 1111 *Rb++[Ro]
      cmd.Op1.type   = o_phrase;
      cmd.Op1.secreg = make_reg((code >> 13) & 0x1F,0);
      break;
  }
  cmd.Op1.reg = make_reg((code >> 18) & 0x1F,0);
  if ( is_store )
    swap_op1_and_op2();
  return cmd.size;
}

//--------------------------------------------------------------------------
//      S UNIT OPERATIONS
//--------------------------------------------------------------------------
static const tmsinsn_t sops[64] =
{                                                               // bits 11..6
  { TMS6_bdec,   t_scst10,      t_none,         t_uint          }, // 00 0000
  { TMS6_add2,   t_i2,          t_xi2,          t_i2            }, // 00 0001
  { TMS6_spdp,   t_none,        t_xsp,          t_dp            }, // 00 0010
  { TMS6_b,      t_none,        t_irp,          t_none          }, // 00 0011
  { TMS6_bnop,   t_none,        t_scst12,       t_ucst3         }, // 00 0100
  { TMS6_addkpc, t_scst7,       t_ucst3,        t_uint          }, // 00 0101
  { TMS6_add,    t_scst5,       t_xsint,        t_sint          }, // 00 0110
  { TMS6_add,    t_sint,        t_xsint,        t_sint          }, // 00 0111
  { TMS6_packhl2,t_i2,          t_xi2,          t_i2            }, // 00 1000
  { TMS6_packh2, t_i2,          t_xi2,          t_i2            }, // 00 1000
  { TMS6_xor,    t_scst5,       t_xuint,        t_uint          }, // 00 1010
  { TMS6_xor,    t_uint,        t_xuint,        t_uint          }, // 00 1011
  { TMS6_null,   t_none,        t_none,         t_none          }, // 00 1100
  { TMS6_b,      t_none,        t_xuint,        t_none          }, // 00 1101
  { TMS6_mvc,    t_none,        t_xuint,        t_cregw         }, // 00 1110
  { TMS6_mvc,    t_none,        t_cregr,        t_uint          }, // 00 1111
  { TMS6_packlh2,t_i2,          t_xi2,          t_i2            }, // 01 0000
  { TMS6_sub2,   t_sint,        t_xsint,        t_sint          }, // 01 0001
  { TMS6_shl,    t_ucst5,       t_xsint,        t_slong         }, // 01 0010
  { TMS6_shl,    t_uint,        t_xsint,        t_slong         }, // 01 0011
  { TMS6_cmpgt2, t_s2,          t_xs2,          t_bv2           }, // 01 0100
  { TMS6_cmpgtu4,t_u4,          t_xu4,          t_bv4           }, // 01 0101
  { TMS6_sub,    t_scst5,       t_xsint,        t_sint          }, // 01 0110
  { TMS6_sub,    t_sint,        t_xsint,        t_sint          }, // 01 0111
  { TMS6_shr2,   t_ucst5,       t_xs2,          t_s2            }, // 01 1000
  { TMS6_shru2,  t_ucst5,       t_xu2,          t_u2            }, // 01 1001
  { TMS6_or,     t_scst5,       t_xuint,        t_uint          }, // 01 1010
  { TMS6_or,     t_uint,        t_xuint,        t_uint          }, // 01 1011
  { TMS6_cmpeq4, t_s4,          t_xs4,          t_bv4           }, // 01 1100
  { TMS6_cmpeq2, t_s2,          t_xs2,          t_bv2           }, // 01 1101
  { TMS6_and,    t_scst5,       t_xuint,        t_uint          }, // 01 1110
  { TMS6_and,    t_uint,        t_xuint,        t_uint          }, // 01 1111
  { TMS6_sadd,   t_sint,        t_xsint,        t_sint          }, // 10 0000
  { TMS6_null,   t_none,        t_none,         t_none          }, // 10 0001
  { TMS6_sshl,   t_ucst5,       t_xsint,        t_sint          }, // 10 0010
  { TMS6_sshl,   t_uint,        t_xsint,        t_sint          }, // 10 0011
  { TMS6_shru,   t_ucst5,       t_ulong,        t_ulong         }, // 10 0100
  { TMS6_shru,   t_uint,        t_ulong,        t_ulong         }, // 10 0101
  { TMS6_shru,   t_ucst5,       t_xuint,        t_uint          }, // 10 0110
  { TMS6_shru,   t_uint,        t_xuint,        t_uint          }, // 10 0111
  { TMS6_cmpeqdp,t_dp,          t_xdp,          t_sint          }, // 10 1000
  { TMS6_cmpgtdp,t_dp,          t_xdp,          t_sint          }, // 10 1001
  { TMS6_cmpltdp,t_dp,          t_xdp,          t_sint          }, // 10 1010
  { TMS6_extu,   t_uint,        t_xuint,        t_uint          }, // 10 1011
  { TMS6_absdp,  t_dp,          t_none,         t_dp            }, // 10 1100
  { TMS6_rcpdp,  t_dp,          t_none,         t_dp            }, // 10 1101
  { TMS6_rsqrdp, t_dp,          t_none,         t_dp            }, // 10 1110
  { TMS6_ext,    t_uint,        t_xsint,        t_sint          }, // 10 1111
  { TMS6_shl,    t_ucst5,       t_slong,        t_slong         }, // 11 0000
  { TMS6_shl,    t_uint,        t_slong,        t_slong         }, // 11 0001
  { TMS6_shl,    t_ucst5,       t_xsint,        t_sint          }, // 11 0010
  { TMS6_shl,    t_uint,        t_xsint,        t_sint          }, // 11 0011
  { TMS6_shr,    t_ucst5,       t_slong,        t_slong         }, // 11 0100
  { TMS6_shr,    t_uint,        t_slong,        t_slong         }, // 11 0101
  { TMS6_shr,    t_ucst5,       t_xsint,        t_sint          }, // 11 0110
  { TMS6_shr,    t_uint,        t_xsint,        t_sint          }, // 11 0111
  { TMS6_cmpeqsp,t_sp,          t_xsp,          t_sint          }, // 11 1000
  { TMS6_cmpgtsp,t_sp,          t_xsp,          t_sint          }, // 11 1001
  { TMS6_cmpltsp,t_sp,          t_xsp,          t_sint          }, // 11 1010
  { TMS6_set,    t_uint,        t_xuint,        t_uint          }, // 11 1011
  { TMS6_abssp,  t_none,        t_xsp,          t_sp            }, // 11 1100
  { TMS6_rcpsp,  t_none,        t_xsp,          t_sp            }, // 11 1101
  { TMS6_rsqrsp, t_none,        t_xsp,          t_sp            }, // 11 1110
  { TMS6_clr,    t_uint,        t_xuint,        t_uint          }, // 11 1111
};

static int s_ops(uint32 code)
{
// +----------------------------------------------------------------+
// |31    29|28|27    23|22   18|17        13|12|11    6|5|4|3|2|1|0|
// |  creg  |z |  dst   |  src2 |  src1/cst  |x |   op  |1|0|0|0|s|p|
// +----------------------------------------------------------------+

  int opcode = (code >> 6) & 0x3F;
  if ( !table_insns(code, sops + opcode, (code & BIT12) != 0) )
    return 0;
  switch ( cmd.itype )
  {
    case TMS6_mvc:
      cmd.cflags &= ~aux_xp;            // XPATH should not be displayed
                                        // (assembler does not like it)
      if ( cmd.funit != FU_S2 )
        return 0;
      break;
    case TMS6_b:
      if ( cmd.funit != FU_S2 )
        return 0;
      if ( opcode != 3 )        // b irp
      {
        switch ( (code >>23) & 0x1F )
        {
          case 0:  // b
            break;
          case 1:  // bnop
            cmd.itype = TMS6_bnop;
            make_op(cmd.Op2, t_ucst3, (code >> 13) & 0x1F, false);
            break;
          default:
            return 0;
        }
      }
      break;
    case TMS6_bdec:
      cmd.cflags &= ~aux_xp;            // XPATH should not be displayed
      if ( (code & BIT12) == 0 )
        cmd.itype = TMS6_bpos;
      break;
    case TMS6_extu:
    case TMS6_ext:
    case TMS6_set:
    case TMS6_clr:
      cmd.cflags &= ~aux_xp;            // XPATH should not be displayed
                                        // (assembler does not like it)
      /* fall thru */
    case TMS6_shl:
    case TMS6_sshl:
    case TMS6_shr:
    case TMS6_shru:
    case TMS6_shr2:
    case TMS6_shru2:
      swap_op1_and_op2();
      break;
    case TMS6_addkpc:
      swap_op2_and_op3();
      break;
  }
  return cmd.size;
}

//--------------------------------------------------------------------------
//      ADDK ON S UNITS
//--------------------------------------------------------------------------
static int addk(uint32 code)
{
// +-----------------------------------------------------+
// |31    29|28|27    23|22               7|6|5|4|3|2|1|0|
// |  creg  |z |  dst   |        cst       |1|0|1|0|0|s|p|
// +-----------------------------------------------------+

  cmd.itype = TMS6_addk;
  cmd.Op1.type = o_imm;
  cmd.Op1.dtyp = dt_word;
  cmd.Op1.value = short(code >> 7);
  cmd.Op2.type = o_reg;
  cmd.Op2.dtyp = dt_dword;
  cmd.Op2.reg  = make_reg((code >> 23) & 0x1F,0);
  return cmd.size;
}

//--------------------------------------------------------------------------
//      FIELD OPERATIONS (IMMEDIATE FORMS) ON S UNITS
//--------------------------------------------------------------------------
static int field_ops(uint32 code)
{
// +---------------------------------------------------------------+
// |31    29|28|27    23|22   18|17    13|12     8|7  6|5|4|3|2|1|0|
// |  creg  |z |  dst   |  src2 |  csta  |  cstb  | op |0|0|1|0|s|p|
// +---------------------------------------------------------------+
  static const uchar itypes[] =
  {
    TMS6_extu,  // 00
    TMS6_ext,   // 01
    TMS6_set,   // 10
    TMS6_clr,   // 11
  };
  cmd.itype = itypes[(code >> 6) & 3];
  cmd.Op1.type  = o_imm;
  cmd.Op1.value = (code >> 13) & 0x1F;
  cmd.Op2.type  = o_imm;
  cmd.Op2.value = (code >>  8) & 0x1F;
  cmd.Op3.type  = o_reg;
  cmd.Op3.reg   = make_reg((code >> 23) & 0x1F,0);
  cmd.Op1.src2  = make_reg((code >> 18) & 0x1F,0);
  cmd.cflags   |= aux_src2;
  return cmd.size;
}

//--------------------------------------------------------------------------
//      MVK AND MVKH ON S UNITS
//--------------------------------------------------------------------------
static int mvk(uint32 code)
{
// +-----------------------------------------------------+
// |31    29|28|27    23|22               7|6|5|4|3|2|1|0|
// |  creg  |z |  dst   |        cst       |x|1|0|1|0|s|p|
// +-----------------------------------------------------+

  cmd.itype     = (code & BIT6) ? TMS6_mvkh : TMS6_mvk;
  cmd.Op1.type  = o_imm;
  cmd.Op1.dtyp  = dt_word;
  cmd.Op1.value = (code >> 7) & 0xFFFF;
  if ( cmd.itype == TMS6_mvkh )
  {
    // we can not use <<= 16 because bcb6 generates wrong code for __EA64__
    cmd.Op1.value = uint32(cmd.Op1.value << 16);
    cmd.Op1.dtyp  = dt_dword;
  }
  cmd.Op2.type  = o_reg;
  cmd.Op2.dtyp  = dt_word;
  cmd.Op2.reg   = make_reg((code >> 23) & 0x1F,0);
  return cmd.size;
}

//--------------------------------------------------------------------------
//      BCOND DISP ON S UNITS
//--------------------------------------------------------------------------
static int bcond(uint32 code)
{
// +--------------------------------------------+
// |31    29|28|27               7|6|5|4|3|2|1|0|
// |  creg  |z |        cst       |0|0|1|0|0|s|p|
// +--------------------------------------------+

  cmd.itype = TMS6_b;
  g_code = code;
  op_near(cmd.Op1, 7, 0x1FFFFF);
  return cmd.size;
}

//--------------------------------------------------------------------------
//      INSTRUCTIONS THAT CAN NOT BE PREDICATED
//--------------------------------------------------------------------------
struct tmsinsn_indexed_t
{
  uchar itype;
  uchar src1;
  uchar src2;
  uchar dst;
  uint32 index;
  uint32 mask;
  funit_t unit;
};
static const tmsinsn_indexed_t nopreds[] =
{                                                  // bits 11..2
  { TMS6_callp,    t_scst21,    t_a3,           t_none,  0x004, 0x01F, FU_S1 },
  { TMS6_addab,    t_b14,       t_ucst15,       t_uint,  0x00F, 0x01F, FU_D1 },
  { TMS6_addad,    t_b14,       t_ucst15,       t_uint,  0x010, 0x01F, FU_D1 },
  { TMS6_addah,    t_b14,       t_ucst15,       t_uint,  0x017, 0x01F, FU_D1 },
  { TMS6_addaw,    t_b14,       t_ucst15,       t_uint,  0x01F, 0x01F, FU_D1 },
  { TMS6_addsub,   t_sint,      t_xsint,        t_dint,  0x066, 0x3FF, FU_L1 },
  { TMS6_saddsub,  t_sint,      t_xsint,        t_dint,  0x076, 0x3FF, FU_L1 },
  { TMS6_dpack2,   t_sint,      t_xsint,        t_dint,  0x1A6, 0x3FF, FU_L1 },
  { TMS6_shfl3,    t_sint,      t_xsint,        t_dint,  0x1B6, 0x3FF, FU_L1 },
  { TMS6_addsub2,  t_sint,      t_xsint,        t_dint,  0x06E, 0x3FF, FU_L1 },
  { TMS6_saddsub2, t_sint,      t_xsint,        t_dint,  0x07E, 0x3FF, FU_L1 },
  { TMS6_dpackx2,  t_sint,      t_xsint,        t_dint,  0x19E, 0x3FF, FU_L1 },
  { TMS6_cmpy,     t_s2,        t_xs2,          t_dint,  0x0AC, 0x3FF, FU_M1 },
  { TMS6_cmpyr,    t_s2,        t_xs2,          t_s2,    0x0BC, 0x3FF, FU_M1 },
  { TMS6_cmpyr1,   t_s2,        t_xs2,          t_s2,    0x0CC, 0x3FF, FU_M1 },
  { TMS6_mpy2ir,   t_sint,      t_xsint,        t_dint,  0x0FC, 0x3FF, FU_M1 },
  { TMS6_ddotpl2r, t_dint,      t_xs2,          t_s2,    0x14C, 0x3FF, FU_M1 },
  { TMS6_ddotph2r, t_dint,      t_xs2,          t_s2,    0x15C, 0x3FF, FU_M1 },
  { TMS6_ddotpl2,  t_dint,      t_xs2,          t_dint,  0x16C, 0x3FF, FU_M1 },
  { TMS6_ddotph2,  t_dint,      t_xs2,          t_dint,  0x17C, 0x3FF, FU_M1 },
  { TMS6_ddotp4,   t_ds2,       t_xs2,          t_dint,  0x18C, 0x3FF, FU_M1 },
  { TMS6_smpy32,   t_sint,      t_xsint,        t_sint,  0x19C, 0x3FF, FU_M1 },
  { TMS6_xormpy,   t_uint,      t_xuint,        t_uint,  0x1BC, 0x3FF, FU_M1 },
  { TMS6_gmpy,     t_uint,      t_xuint,        t_uint,  0x1FC, 0x3FF, FU_M1 },
  { TMS6_rpack2,   t_sint,      t_xsint,        t_s2,    0x3BC, 0x3FF, FU_S1 },
  { TMS6_swe,      t_none,      t_none,         t_none,  0x0000000, 0x3FFFFFF, FU_NONE },
  { TMS6_dint,     t_none,      t_none,         t_none,  0x0001000, 0x3FFFFFF, FU_NONE },
  { TMS6_swenr,    t_none,      t_none,         t_none,  0x0002000, 0x3FFFFFF, FU_NONE },
  { TMS6_rint,     t_none,      t_none,         t_none,  0x0001400, 0x3FFFFFF, FU_NONE },
};

static int nopred(uint32 code)
{
  int idx = (code >> 2) & 0x3FFFFFF;
  const tmsinsn_indexed_t *p = nopreds;
  for ( int i=0; i < qnumber(nopreds); i++,p++ )
  {
    if ( p->index == (idx & p->mask) )
    {
      cmd.funit = p->unit + ((code & BIT1) >> 1);
      bool other = (code & BIT1) != 0;
      if ( p->unit == FU_M1 || p->unit == FU_L1 )
        other = (code & BIT12) != 0;
      int size = table_insns(code, (tmsinsn_t *)p, other);
      if ( p->src1 == t_b14 )
        cmd.cflags &= ~aux_xp;
      return size;
    }
  }
  return 0;
}

//--------------------------------------------------------------------------
int idaapi ana(void)
{
  if ( cmd.ip & 3 )
    return 0;           // alignment error

  uint32 code = ua_next_long();

  if ( code & BIT0 )
    cmd.cflags |= aux_para;     // parallel execution with the next insn

  cmd.cond = (code >> 28);
  switch ( cmd.cond )
  {
    case 0x0: // 0000 unconditional
    case 0x2: // 0010 B0
    case 0x3: // 0011 !B0
    case 0x4: // 0100 B1
    case 0x5: // 0101 !B1
    case 0x6: // 0110 B2
    case 0x7: // 0111 !B2
    case 0x8: // 1000 A1
    case 0x9: // 1001 !A1
    case 0xA: // 1010 A2
    case 0xB: // 1011 !A2
    case 0xC: // 1100 A0
    case 0xD: // 1101 !A0
      break;
    case 0xE: // 1110 reserved
    case 0xF: // 1111 reserved
      return 0;
    case 0x1: // 0001 no predicate
      cmd.cond = 0;
      return nopred(code);
  }

  switch ( (code >> 2) & 0x1F )
  {
//
//      Operations on L units
//
    case 0x06: // 00110
    case 0x0E: // 01110
    case 0x16: // 10110
    case 0x1E: // 11110
      cmd.funit = (code & BIT1) ? FU_L2 : FU_L1;
      return l_ops(code);
//
//      Operations on M units
//
    case 0x00: // 00000
      if ( (code & 0x3FFFCL) == 0x1E000L )
      {
        cmd.itype = TMS6_idle;
        return cmd.size;
      }
      if ( (code & 0x21FFEL) == 0 )
      {
        cmd.Op1.type = o_imm;
        cmd.Op1.dtyp = dt_dword;
        cmd.Op1.value = ((code >> 13) & 0xF) + 1;
        if ( cmd.Op1.value > 9 )
          return 0;
        if ( cmd.Op1.value == 1 )
          cmd.Op1.clr_showed();
        cmd.itype = TMS6_nop;
        return cmd.size;
      }
      if ( (code & 0x0C03FFFC) == 0x32000 )
      {
        cmd.itype = TMS6_spmaskr;
        return op_spmask(cmd.Op1, code);
      }
      if ( (code & 0x0C03FFFC) == 0x30000 )
      {
        cmd.itype = TMS6_spmask;
        return op_spmask(cmd.Op1, code);
      }
      if ( (code & 0x371FFC) == 0x030000 )
      {
        static const uchar itypes[] =
        {
          TMS6_null,   TMS6_null,    TMS6_spkernel,  TMS6_spkernelr,
          TMS6_sploop, TMS6_sploopd, TMS6_null,      TMS6_sploopw,
        };
        int idx = (code >> 13) & 7;
        cmd.itype = itypes[idx];
        switch ( idx )
        {
          default:
            return 0;
          case 2:               // spkernel
            cmd.Op1.type = o_stgcyc;
            cmd.Op1.dtyp = dt_dword;
            cmd.Op1.value = ((code >> 22) & 0x3F);
            break;
          case 3:               // spkernelr
            break;
          case 4:               // sploop
          case 5:               // sploopd
          case 7:               // sploopw
            cmd.Op1.type = o_imm;
            cmd.Op1.dtyp = dt_dword;
            cmd.Op1.value = ((code >> 23) & 0x1F) + 1;
            break;

        }
        return cmd.size;
      }
      cmd.funit = (code & BIT1) ? FU_M2 : FU_M1;
      return m_ops(code);
//
//      Operations on D units
//
    case 0x10: // 10000
      cmd.funit = (code & BIT1) ? FU_D2 : FU_D1;
      return d_ops(code);
//
//      Operations on D units (with crosss path)
//
    case 0x0C: // 01100
      cmd.funit = (code & BIT1) ? FU_D2 : FU_D1;
      return dx_ops(code);
//
//      Operations on D units (crosss path used with a constant)
//
    case 0x1C: // 11100
      cmd.funit = (code & BIT1) ? FU_D2 : FU_D1;
      return dxc_ops(code);
//
//      Load/store with 15-bit offset (on D2 unit)
//
    case 0x03: // 00011
    case 0x07: // 00111
    case 0x0B: // 01011
    case 0x0F: // 01111
    case 0x13: // 10011
    case 0x17: // 10111
    case 0x1B: // 11011
    case 0x1F: // 11111
      cmd.funit = FU_D2;
      return ld15(code);
//
//      Load/store baseR+offsetR/const (on D units)
//
    case 0x01: // 00001
    case 0x05: // 00101
    case 0x09: // 01001
    case 0x0D: // 01101
    case 0x11: // 10001
    case 0x15: // 10101
    case 0x19: // 11001
    case 0x1D: // 11101
      cmd.funit = (code & BIT7) ? FU_D2 : FU_D1;
      return ldbase(code);
//
//      Operations on S units
//
    case 0x08: // 01000
    case 0x18: // 11000
      cmd.funit = (code & BIT1) ? FU_S2 : FU_S1;
      return s_ops(code);
//
//      ADDK on S units
//
    case 0x14: // 10100
      cmd.funit = (code & BIT1) ? FU_S2 : FU_S1;
      return addk(code);
//
//      Field operations (immediate forms) on S units
//
    case 0x02: // 00010
    case 0x12: // 10010
      cmd.funit = (code & BIT1) ? FU_S2 : FU_S1;
      return field_ops(code);
//
//      MVK and MVKH on S units
//
    case 0x0A: // 01010
    case 0x1A: // 11010
      cmd.funit = (code & BIT1) ? FU_S2 : FU_S1;
      return mvk(code);
//
//      Bcond disp on S units
//
    case 0x04: // 00100
      cmd.funit = (code & BIT1) ? FU_S2 : FU_S1;
      return bcond(code);
  }
  return 0;
}

