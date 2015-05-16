/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "f2mc.hpp"
#include <srarea.hpp>
#include <frame.hpp>

static bool flow;

//------------------------------------------------------------------------
int get_reglist_size(ushort reglist)
{
  int size = 0;
  for (int i = 0; i < 8; i++)
    if ( (reglist >> i) & 1 )
      size++;
  return size;
}

//------------------------------------------------------------------------
bool is_bank(op_t &op)
{
  if ( op.type != o_reg ) return false;
  return (op.reg == DTB || op.reg == ADB || op.reg == SSB
    || op.reg == USB || op.reg == DPR || op.reg == PCB);
}

//----------------------------------------------------------------------
static void process_imm(op_t &x)
{
  doImmd(cmd.ea);
  if ( isDefArg(uFlag,x.n) ) return; // if already defined by user
  switch ( cmd.itype )
  {
    case F2MC_add:
    case F2MC_addl:
    case F2MC_addsp:
    case F2MC_addw2:
    case F2MC_and:
    case F2MC_andw2:
    case F2MC_callv:
    case F2MC_cbne:
    case F2MC_cmp2:
    case F2MC_cmpl:
    case F2MC_cmpw2:
    case F2MC_cwbne:
    case F2MC_int:
    case F2MC_link:
    case F2MC_mov:
    case F2MC_movl:
    case F2MC_movn:
    case F2MC_movw:
    case F2MC_movx:
    case F2MC_or:
    case F2MC_orw2:
    case F2MC_sub:
    case F2MC_subl:
    case F2MC_subw2:
    case F2MC_xor:
    case F2MC_xorw2:
      op_num(cmd.ea, x.n);
  }
}

//----------------------------------------------------------------------
static void process_operand(op_t &x, int use)
{
  switch ( x.type )
  {
    case o_reg:
    case o_phrase:
    case o_reglist:
      return;

    case o_near:
      {
        cref_t ftype = fl_JN;
        ea_t ea = calc_code_mem(x.addr);
        if ( InstrIsSet(cmd.itype, CF_CALL) )
        {
          if ( !func_does_return(ea) )
            flow = false;
          ftype = fl_CN;
        }
        ua_add_cref(x.offb, ea, ftype);
      }
      break;

    case o_imm:
      if ( !use ) error("interr: emu");
      process_imm(x);
      if ( isOff(uFlag, x.n) )
        ua_add_off_drefs2(x, dr_O, OOFS_IFSIGN);
      break;

    case o_mem:
      {
        ea_t ea = calc_data_mem(x.addr);
        ua_add_dref(x.offb, ea, use ? dr_R : dr_W);
        ua_dodata2(x.offb, ea, x.dtyp);
        if ( !use )
          doVar(ea);
      }
      break;
    case o_displ:
      process_imm(x);
      if ( may_create_stkvars() && x.reg == RW3)
      {
        func_t *pfn = get_func(cmd.ea);
        if ( pfn != NULL
         && (pfn->flags & FUNC_FRAME) != 0
         && ua_stkvar2(x, x.addr, STKVAR_VALID_SIZE) )
        {
          op_stkvar(cmd.ea, x.n);
        }
      }
      break;

    default:
      warning("%a: %s,%d: bad optype %d", cmd.ea, cmd.get_canon_mnem(), x.n, x.type);
  }
}

//----------------------------------------------------------------------
inline bool add_stkpnt(func_t *pfn, sval_t delta)
{
  return add_auto_stkpnt2(pfn, cmd.ea+cmd.size, delta);
}

//----------------------------------------------------------------------
static void trace_sp(void)
{
  func_t *pfn = get_func(cmd.ea);
  if ( pfn == NULL )
    return;

  switch ( cmd.itype )
  {
    case F2MC_int:
    case F2MC_intp:
    case F2MC_int9:
      add_stkpnt(pfn, -6*2);
      break;
    case F2MC_reti:
      add_stkpnt(pfn, 6*2);
      break;
    case F2MC_link:
      add_stkpnt(pfn, -2-cmd.Op1.value);
      break;
    case F2MC_unlink:
      add_stkpnt(pfn, -get_spd(pfn, cmd.ea));
      break;
    case F2MC_ret:
      add_stkpnt(pfn, 2);
      break;
    case F2MC_retp:
      add_stkpnt(pfn, 2*2);
      break;
    case F2MC_pushw:
      if ( cmd.Op1.type == o_reglist )
        add_stkpnt(pfn, -get_reglist_size(cmd.Op1.reg)*2);
      else add_stkpnt(pfn, -2);
      break;
    case F2MC_popw:
      if ( cmd.Op1.type == o_reglist )
        add_stkpnt(pfn, get_reglist_size(cmd.Op1.reg)*2);
      else add_stkpnt(pfn, 2);
      break;
    case F2MC_addsp:
      add_stkpnt(pfn, cmd.Op1.value);
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

  if ( feature & CF_CHG1 ) process_operand(cmd.Op1, 0);
  if ( feature & CF_CHG2 ) process_operand(cmd.Op2, 0);
  if ( feature & CF_CHG3 ) process_operand(cmd.Op3, 0);

  // check for CCR changes
  if ( cmd.Op1.type == o_reg && cmd.Op1.reg == CCR )
  {
    op_bin(cmd.ea, 1);

    sel_t ccr = getSR(cmd.ea, CCR);
    if ( ccr == BADSEL ) ccr = 0;

    if ( cmd.itype == F2MC_and ) ccr &= cmd.Op2.value;     // and ccr,imm8
    else if ( cmd.itype == F2MC_or ) ccr |= cmd.Op2.value; // or  ccr,imm8
    splitSRarea1(get_item_end(cmd.ea), CCR, ccr, SR_auto);
  }


  // check for DTB,ADB,SSB,USB,DPR changes
  if ( cmd.itype == F2MC_mov && is_bank(cmd.Op1)
    && cmd.Op2.type == o_reg && cmd.Op2.reg == A ) // mov dtb|adb|ssb|usb|dpr,a
  {
    insn_t saved = cmd;
    sel_t bank = BADSEL;
    if ( decode_prev_insn(cmd.ea) != BADADDR && cmd.itype == F2MC_mov
      && cmd.Op1.type == o_reg && cmd.Op1.reg == A )
    {
      if ( cmd.Op2.type == o_imm ) // mov a,imm8
        bank = cmd.Op2.value;
      else if ( is_bank(cmd.Op2) ) // mov a,dtb|adb|ssb|usb|dpr|pcb
      {
        bank = getSR(cmd.ea, cmd.Op2.reg);
        if ( bank == BADSEL ) bank = 0;
      }
    }
    cmd = saved;
    if ( bank != BADSEL )
      splitSRarea1(get_item_end(cmd.ea), cmd.Op1.reg, bank, SR_auto);
  }


  // determine if the next instruction should be executed
  if ( segtype(cmd.ea) == SEG_XTRN )
    flow = false;
  if ( flow )
    ua_add_cref(0,cmd.ea+cmd.size,fl_F);

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
      if ( ea + 4 < pfn->endEA) // minimum 2+1+1 bytes needed
      {
        decode_insn(ea);
        if ( cmd.itype == F2MC_link )
        {
          size_t localsize = (size_t)cmd.Op1.value;
          ushort regsize   = 2;
          decode_insn(ea+2);
          setflag((uint32 &)pfn->flags,FUNC_FRAME,1);
          return add_frame(pfn, localsize, regsize, 0);
        }
      }
    }
  }
  return 0;
}

//----------------------------------------------------------------------
int idaapi is_sp_based(const op_t &)
{
  return OP_SP_ADD | OP_FP_BASED;
}
