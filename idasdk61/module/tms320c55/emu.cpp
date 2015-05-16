/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "tms320c55.hpp"
#include <srarea.hpp>
#include <frame.hpp>

static int flow;

//------------------------------------------------------------------------
ea_t calc_data_mem(op_t &op)
{
  ea_t addr = op.addr;
  sel_t dph = 0;
  if ( op.tms_regH == DPH )
  {
    dph = getSR(toEA(cmd.cs, cmd.ip), DPH);
    if ( dph == BADSEL ) return BADSEL;
    addr &= 0xFFFF;
  }
  sel_t dp = 0;
  if ( op.tms_regP == DP )
  {
    dp = getSR(toEA(cmd.cs, cmd.ip), DP);
    if ( dp == BADSEL ) return BADSEL;
    addr &= 0xFFFF;
  }
  return (((dph & 0x7F) << 16) | (dp + addr)) << 1;
}

ea_t calc_io_mem(op_t &op)
{
  ea_t addr = op.addr;
  sel_t pdp = 0;
  if ( op.tms_regP == PDP )
  {
    pdp = getSR(toEA(cmd.cs, cmd.ip), PDP);
    if ( pdp == BADSEL ) return BADSEL;
    addr &= 0x7F;
  }
  ea_t ea = ((pdp & 0x1FF) << 7) | addr;
  return toEA(cmd.cs, ea);
}

//----------------------------------------------------------------------
int get_mapped_register(ea_t ea)
{
  ea = ea >> 1;
  if ( idpflags & TMS320C55_MMR )
  {
    int registers[] =
    {
      IER0,   IFR0,  ST0_55, ST1_55, ST3_55, -1,    ST0,   ST1,
      AC0L,   AC0H,  AC0G,   AC1L,   AC1H,   AC1G,  T3,    TRN0,
      AR0,    AR1,   AR2,    AR3,    AR4,    AR5,   AR6,   AR7,
      SP,     BK03,  BRC0,   RSA0L,  REA0L,  PMST,  XPC,   -1,
      T0,     T1,    T2,     T3,     AC2L,   AC2H,  AC2G,  CDP,
      AC3L,   AC3H,  AC3H,   DPH,    -1,     -1,    DP,    PDP,
      BK47,   BKC,   BSA01,  BSA23,  BSA45,  BSA67, BSAC,  -1,
      TRN1,   BRC1,  BRS1,   CSR,    RSA0H,  RSA0L, REA0H, REA0L,
      RSA1H,  RSA1L, REA1H,  REA1L,  RPTC,   IER1,  IFR1,  DBIER0,
      DBIER1, IVPD,  IVPH,   ST2_55, SSP,    SP,    SPH,   CDPH
    };
    if ( ea <= 0x4F) return registers[int(ea )];
  }
  return -1;
}

//----------------------------------------------------------------------
static void process_imm(op_t &x)
{
  doImmd(cmd.ea); // assign contextual menu for conversions
  if ( isDefArg(uFlag,x.n) ) return; // if already defined by user
  switch ( cmd.itype )
  {
    case TMS320C55_rptcc:
    case TMS320C55_rpt:
    case TMS320C55_aadd:
    case TMS320C55_amov:
    case TMS320C55_asub:
    case TMS320C55_mov2:
    case TMS320C55_and3:
    case TMS320C55_or3:
    case TMS320C55_xor2:
    case TMS320C55_xor3:
    case TMS320C55_mpyk2:
    case TMS320C55_mpyk3:
    case TMS320C55_mpykr2:
    case TMS320C55_mpykr3:
    case TMS320C55_mack3:
    case TMS320C55_mack4:
    case TMS320C55_mackr3:
    case TMS320C55_mackr4:
    case TMS320C55_bclr2:
    case TMS320C55_bset2:
    case TMS320C55_rptadd:
    case TMS320C55_rptsub:
    case TMS320C55_add2:
    case TMS320C55_add3:
    case TMS320C55_sub2:
    case TMS320C55_sub3:
    case TMS320C55_and2:
    case TMS320C55_or2:
    case TMS320C55_intr:
    case TMS320C55_trap:
    case TMS320C55_btst:
      op_num(cmd.ea, x.n);
  }
}

//----------------------------------------------------------------------
static void process_operand(op_t &op, int use)
{
  switch ( op.type )
  {
    case o_cond:
    case o_shift:
    case o_io:
      return;

    case o_reg:
      // analyze immediate values
      if (op.tms_modifier == TMS_MODIFIER_REG_OFFSET || op.tms_modifier == TMS_MODIFIER_P_REG_OFFSET
        || op.tms_modifier == TMS_MODIFIER_REG_SHORT_OFFSET)
        doImmd(cmd.ea);
      // analyze local vars
      if ( op.reg == SP && op.tms_modifier == TMS_MODIFIER_REG_OFFSET )
      {
        if ( may_create_stkvars()
          && get_func(cmd.ea) != NULL
          && ua_stkvar2(op, 2 * op.value, STKVAR_VALID_SIZE))
        {
          op_stkvar(cmd.ea, op.n);
        }
      }
      // DP, DPH and PDP unknown changes
      if ( !use )
      {
        if ( op.reg == DP || op.reg == DPH || op.reg == PDP )
          splitSRarea1(get_item_end(cmd.ea), op.reg, BADSEL, SR_auto);
      }
      break;

    case o_relop: // analyze immediate value
      if ( op.tms_relop_type == TMS_RELOP_IMM )
        doImmd(cmd.ea);
      break;

    case o_near:
      {
        if ( cmd.itype != TMS320C55_rptb && cmd.itype != TMS320C55_rptblocal )
        {
          cref_t ftype = fl_JN;
          ea_t ea = calc_code_mem(op.addr);
          if ( InstrIsSet(cmd.itype, CF_CALL) )
          {
            if ( !func_does_return(ea) )
              flow = false;
            ftype = fl_CN;
          }
#ifndef TMS320C55_NO_NAME_NO_REF
          ua_add_cref(op.offb, ea, ftype);
#endif
        }

#ifndef TMS320C55_NO_NAME_NO_REF
        else // evaluate RPTB loops as dref
          ua_add_dref(op.offb, calc_code_mem(op.addr), dr_I);
#endif
        break;
      }

    case o_imm:
      if ( !use ) error("interr: emu");
      process_imm(op);
#ifndef TMS320C55_NO_NAME_NO_REF
      if ( isOff(uFlag, op.n) )
        ua_add_off_drefs2(op, dr_O, op.tms_signed ? OOF_SIGNED : 0);
#endif
      break;

    case o_mem:
      {
        ea_t ea = calc_data_mem(op);
        if ( ea != BADADDR )
        {
#ifndef TMS320C55_NO_NAME_NO_REF
          ua_add_dref(op.offb, ea, use ? dr_R : dr_W);
#endif
          ua_dodata2(op.offb, ea, op.dtyp);
          if ( !use )
          {
            int reg = get_mapped_register(ea);
            if ( reg == DP || reg == DPH || reg == PDP )
              splitSRarea1(get_item_end(cmd.ea), reg, BADSEL, SR_auto);
            doVar(ea);
          }
        }
      }
      break;

    default:
      warning("interr: emu2 address:%a operand:%d type:%d", cmd.ea, op.n, op.type);
  }
}

//----------------------------------------------------------------------
static bool add_stkpnt(sval_t delta)
{
  func_t *pfn = get_func(cmd.ea);
  if ( pfn == NULL )
    return false;

  return add_auto_stkpnt2(pfn, cmd.ea+cmd.size, delta);
}

//----------------------------------------------------------------------
static void trace_sp(void)
{
  switch ( cmd.itype )
  {
    case TMS320C55_pop1: // pop dst; pop dbl(ACx); pop Smem; pop dbl(Lmem)
      add_stkpnt((cmd.Op1.tms_operator1 & TMS_OPERATOR_DBL) ? 4:2);
      break;
    case TMS320C55_pop2: // pop dst1, dst2; pop dst, Smem
      add_stkpnt(4);
      break;
    case TMS320C55_psh1: // psh dst; psh dbl(ACx); psh Smem; psh dbl(Lmem)
      add_stkpnt((cmd.Op1.tms_operator1 & TMS_OPERATOR_DBL) ? -4:-2);
      break;
    case TMS320C55_psh2: // psh src1, src2; psh src, Smem
      add_stkpnt(-4);
      break;
    case TMS320C55_popboth:
    case TMS320C55_ret:
      add_stkpnt(2);
      break;
    case TMS320C55_pshboth:
      add_stkpnt(-2);
      break;
    case TMS320C55_reti:
      add_stkpnt(6);
      break;
    case TMS320C55_aadd:
      if ( cmd.Op2.type == o_reg && cmd.Op2.reg == SP && cmd.Op1.type == o_imm )
        add_stkpnt(2 * cmd.Op1.value);
      break;
  }
}

//----------------------------------------------------------------------
int idaapi emu(void)
{
  uint32 feature = cmd.get_canon_feature();
  flow = (feature & CF_STOP) == 0;

  if ( feature & CF_USE1 ) process_operand(cmd.Op1, 1);
  if ( feature & CF_USE2 ) process_operand(cmd.Op2, 1);
  if ( feature & CF_USE3 ) process_operand(cmd.Op3, 1);
  if ( feature & CF_USE4 ) process_operand(cmd.Op4, 1);
  if ( feature & CF_USE5 ) process_operand(cmd.Op5, 1);
  if ( feature & CF_USE6 ) process_operand(cmd.Op6, 1);

  if ( feature & CF_CHG1 ) process_operand(cmd.Op1, 0);
  if ( feature & CF_CHG2 ) process_operand(cmd.Op2, 0);
  if ( feature & CF_CHG3 ) process_operand(cmd.Op3, 0);
  if ( feature & CF_CHG4 ) process_operand(cmd.Op4, 0);
  if ( feature & CF_CHG5 ) process_operand(cmd.Op5, 0);
  if ( feature & CF_CHG6 ) process_operand(cmd.Op6, 0);

  // CPL and ARMS status flags changes
  if ( (cmd.itype == TMS320C55_bclr1 || cmd.itype == TMS320C55_bset1 )
    && cmd.Op1.type == o_reg
    && (cmd.Op1.reg == CPL || cmd.Op1.reg == ARMS))
      splitSRarea1(get_item_end(cmd.ea), cmd.Op1.reg, cmd.itype == TMS320C55_bclr1 ? 0 : 1, SR_auto);

  // DP, DPH and PDP changes
  if ( cmd.itype == TMS320C55_mov2 && cmd.Op2.type == o_reg && cmd.Op1.type == o_imm )
  {
    if ( cmd.Op2.reg == DP )
      splitSRarea1(get_item_end(cmd.ea), DP, cmd.Op1.value & 0xFFFF, SR_auto);
    else if ( cmd.Op2.reg == DPH )
      splitSRarea1(get_item_end(cmd.ea), DPH, cmd.Op1.value & 0x7F, SR_auto);
    else if ( cmd.Op2.reg == PDP )
      splitSRarea1(get_item_end(cmd.ea), PDP, cmd.Op1.value & 0x1FF, SR_auto);
  }

  // determine if the next instruction should be executed
  if ( segtype(cmd.ea) == SEG_XTRN ) flow = 0;
  if ( flow ) ua_add_cref(0,cmd.ea+cmd.size,fl_F);

  if ( may_trace_sp() )
  {
    if ( !flow )
      recalc_spd(cmd.ea);     // recalculate SP register for the next insn
    else
      trace_sp();
  }
  return 1;
}

//----------------------------------------------------------------------
bool idaapi create_func_frame(func_t *pfn)
{
  if ( pfn != NULL )
  {
    if ( pfn->frame == BADNODE )
    {
      ea_t ea = pfn->startEA;
      ushort regsize = 0;
      while ( ea < pfn->endEA ) // check for register pushs
      {
        decode_insn(ea);
        ea += cmd.size;
        if ( cmd.itype == TMS320C55_psh1 )
          regsize += (cmd.Op1.tms_operator1 & TMS_OPERATOR_DBL) ? 4 : 2;
        else if ( cmd.itype == TMS320C55_psh2 )
          regsize += 4;
        else if ( cmd.itype == TMS320C55_pshboth )
          regsize += 2;
        else break;
      }
      int localsize = 0;
      while ( ea < pfn->endEA ) // check for frame creation
      {
        if ( !decode_insn(ea) )
          break;
        ea += cmd.size;
        if (cmd.itype == TMS320C55_aadd && cmd.Op2.type == o_reg && cmd.Op2.reg == SP
          && cmd.Op1.type == o_imm)
        {
          localsize = int(2 * cmd.Op1.value);
          break;
        }
      }
      add_frame(pfn, localsize, regsize, 0);
    }
  }
  return 0;
}

//----------------------------------------------------------------------
int idaapi is_align_insn(ea_t ea)
{
  if ( !decode_insn(ea) ) return 0;
  switch ( cmd.itype )
  {
    case TMS320C55_nop:
    case TMS320C55_nop_16:
      break;
    default:
      return 0;
  }
  return cmd.size;
}

//----------------------------------------------------------------------
bool idaapi can_have_type(op_t &op)
{
  switch ( op.type )
  {
    case o_io:
    case o_reg:
    case o_relop:
    case o_imm:
      return true;
  }
  return false;
}
