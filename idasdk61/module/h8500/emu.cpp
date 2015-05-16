/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "h8500.hpp"
#include <frame.hpp>

static bool flow;
//------------------------------------------------------------------------
static void process_immediate_number(int n)
{
  doImmd(cmd.ea);
  if ( isDefArg(uFlag,n) ) return;
  switch ( cmd.itype )
  {
    case H8500_add_q:
    case H8500_bclr:
    case H8500_bnot:
    case H8500_bset:
    case H8500_btst:
      op_dec(cmd.ea, n);
      break;
    case H8500_and:
    case H8500_or:
    case H8500_xor:
    case H8500_andc:
    case H8500_orc:
    case H8500_xorc:
      op_num(cmd.ea, n);
      break;
  }
}

//----------------------------------------------------------------------
inline bool issp(int x)
{
  return x == SP;
}

inline bool isbp(int x)
{
  return x == FP;
}

//----------------------------------------------------------------------
int idaapi is_sp_based(const op_t &x)
{
  return OP_SP_ADD |
    ((x.type != o_displ || x.type != o_phrase) && issp(x.phrase) ? OP_SP_BASED : OP_FP_BASED);
}

//----------------------------------------------------------------------
static void add_stkpnt(sval_t value)
{
  func_t *pfn = get_func(cmd.ea);
  if ( pfn == NULL )
    return;

  if ( value & 1 )
    value++;

  add_auto_stkpnt2(pfn, cmd.ea+cmd.size, value);
}

//----------------------------------------------------------------------
inline bool is_mov(int itype)
{
  return itype >= H8500_mov_g && itype <= H8500_mov_s;
}

//----------------------------------------------------------------------
static bool get_op_value(op_t &x, int *value)
{
  if ( x.type == o_imm )
  {
    *value = (int)x.value;
    return true;
  }
  bool ok = false;
  if ( x.type == o_reg )
  {
    int reg = x.reg;
    insn_t saved = cmd;
    if ( decode_prev_insn(cmd.ea) != BADADDR
      && is_mov(cmd.itype)
      && cmd.Op1.type == o_imm
      && cmd.Op2.type == o_reg
      && cmd.Op2.reg  == reg )
    {
      *value = (int)cmd.Op1.value;
      ok = true;
    }
    cmd = saved;
  }
  return ok;
}

//----------------------------------------------------------------------
static int calc_reglist_count(int regs)
{
  int count = 0;
  for ( int i=0; i < 8; i++,regs>>=1 )
    if ( regs & 1 ) count++;
  return count;
}

//----------------------------------------------------------------------
// @--sp
inline bool is_sp_dec(const op_t &x)
{
  return x.type == o_phrase
      && issp(x.reg)
      && x.phtype == ph_pre;
}

//----------------------------------------------------------------------
// @sp++
inline bool is_sp_inc(const op_t &x)
{
  return x.type == o_phrase
      && issp(x.reg)
      && x.phtype == ph_post;
}

//----------------------------------------------------------------------
static void trace_sp(void)
{
  // @sp++
  if ( is_sp_inc(cmd.Op1) )
  {
    int size = 2;
    if ( cmd.Op2.type == o_reglist )
      size *= calc_reglist_count(cmd.Op2.reg);
    add_stkpnt(size);
    return;
  }

  // @--sp
  if ( is_sp_dec(cmd.Op2) )
  {
    int size = 2;
    if ( cmd.Op1.type == o_reglist )
      size *= calc_reglist_count(cmd.Op1.reg);
    add_stkpnt(-size);
    return;
  }
  // xxx @--sp
  if ( is_sp_dec(cmd.Op1) )
  {
    add_stkpnt(-2);
    return;
  }

  int v;
  switch ( cmd.itype )
  {
    case H8500_add_g:
    case H8500_add_q:
    case H8500_adds:
      if ( issp(cmd.Op2.reg) && get_op_value(cmd.Op1, &v) )
        add_stkpnt(v);
      break;
    case H8500_sub:
    case H8500_subs:
      if ( issp(cmd.Op2.reg) && get_op_value(cmd.Op1, &v) )
        add_stkpnt(-v);
      break;
  }
}

//----------------------------------------------------------------------
static sval_t calc_func_call_delta(ea_t callee)
{
  sval_t delta;
  func_t *pfn = get_func(callee);
  if ( pfn != NULL )
  {
    delta = pfn->argsize;
    if ( (pfn->flags & FUNC_FAR) != 0 && cmd.Op1.type == o_near )
      delta += 2; // function will pop the code segment
  }
  else
  {
    delta = get_ind_purged(callee);
    if ( delta == -1 )
      delta = 0;
  }
  return delta;
}

//----------------------------------------------------------------------
// trace a function call.
// adjuct the stack, determine the execution flow
// returns:
//      true  - the called function returns to the caller
//      false - the called function doesn't return to the caller
static bool handle_function_call(ea_t callee)
{
  bool flow = true;
  if ( !func_does_return(callee) )
    flow = false;
  if ( should_trace_sp() )
  {
    func_t *caller = get_func(cmd.ea);
    if ( func_contains(caller, cmd.ea+cmd.size) )
    {
      sval_t delta = calc_func_call_delta(callee);
      if ( delta != 0 )
        add_stkpnt(delta);
    }
  }
  return flow;
}

//----------------------------------------------------------------------
inline ea_t find_callee(void)
{
  return get_first_fcref_from(cmd.ea);
}

//----------------------------------------------------------------------
static void process_operand(op_t &x,int isAlt,int isload)
{
  switch ( x.type )
  {
    case o_reg:
    case o_reglist:
      return;
    case o_imm:
      if ( !isload ) interr("emu");
      process_immediate_number(x.n);
      if ( isOff(uFlag, x.n) )
        ua_add_off_drefs2(x, dr_O, calc_opimm_flags());
      break;
    case o_phrase:
    case o_displ:
      process_immediate_number(x.n);
      if ( isAlt ) break;
      if ( isOff(uFlag, x.n) )
      {
        ua_add_off_drefs2(x, isload ? dr_R : dr_W, calc_opdispl_flags());
        ea_t ea = calc_target(cmd.ea+x.offb, cmd.ea, x.n, x.addr);
        ua_dodata2(x.offb, ea, x.dtyp);
        if ( !isload )
          doVar(ea);
      }
      // create stack variables if required
      if ( x.type == o_displ
        && may_create_stkvars()
        && !isDefArg(uFlag, x.n) )
      {
        func_t *pfn = get_func(cmd.ea);
        if ( pfn != NULL
          && (issp(x.phrase)
              || isbp(x.phrase) && (pfn->flags & FUNC_FRAME) != 0) )
        {
          if ( ua_stkvar2(x, x.addr, STKVAR_VALID_SIZE) )
            op_stkvar(cmd.ea, x.n);
        }
      }
      break;
    case o_near:
    case o_far:
      {
        cref_t ftype = x.type == o_near ? fl_JN : fl_JF;
        ea_t ea = calc_mem(x);
        if ( InstrIsSet(cmd.itype, CF_CALL) )
        {
          if ( !func_does_return(ea) )
            flow = false;
          ftype = x.type == o_near ? fl_CN : fl_CF;
        }
        ua_add_cref(x.offb, ea, ftype);
      }
      break;
    case o_mem:
      {
        ea_t ea = calc_mem(x);
        ua_add_dref(x.offb, ea, isload ? dr_R : dr_W);
        ua_dodata2(x.offb, ea, x.dtyp);
        if ( !isload ) doVar(ea);
      }
      break;
    default:
      interr("emu");
  }
}

//----------------------------------------------------------------------
inline bool is_far_ending(void)
{
  return cmd.itype == H8500_prts
      || cmd.itype == H8500_prtd;
}

//----------------------------------------------------------------------
int idaapi emu(void)
{
  uint32 Feature = cmd.get_canon_feature();
  int flag1 = is_forced_operand(cmd.ea, 0);
  int flag2 = is_forced_operand(cmd.ea, 1);
  int flag3 = is_forced_operand(cmd.ea, 2);

  flow = ((Feature & CF_STOP) == 0);

  if ( Feature & CF_USE1 ) process_operand(cmd.Op1, flag1, 1);
  if ( Feature & CF_USE2 ) process_operand(cmd.Op2, flag2, 1);
  if ( Feature & CF_USE3 ) process_operand(cmd.Op3, flag3, 1);

  if ( Feature & CF_CHG1 ) process_operand(cmd.Op1, flag1, 0);
  if ( Feature & CF_CHG2 ) process_operand(cmd.Op2, flag2, 0);
  if ( Feature & CF_CHG3 ) process_operand(cmd.Op3, flag3, 0);

//
//      Determine if the next instruction should be executed
//
  if ( segtype(cmd.ea) == SEG_XTRN )
     flow = false;

//
// Handle loads to segment registers
//
  sel_t v = BADSEL;
  switch ( cmd.itype )
  {
    case H8500_andc:
      if ( cmd.Op1.value == 0 )
        v = 0;
      goto SPLIT;
    case H8500_orc:
      if ( cmd.Op1.value == 0xFF )
        v = 0xFF;
      goto SPLIT;
    case H8500_ldc:
      if ( cmd.Op1.type == o_imm )
        v = cmd.Op1.value;
    case H8500_xorc:
SPLIT:
      if ( cmd.Op2.reg >= BR && cmd.Op2.reg <= TP )
        splitSRarea1(cmd.ea+cmd.size, cmd.Op2.reg, v, SR_auto);
      break;
  }

  if ( (Feature & CF_CALL) != 0 )
  {
    ea_t callee = find_callee();
    if ( !handle_function_call(callee) )
      flow = false;
  }

//
//      Handle SP modifications
//
  if ( may_trace_sp() )
  {
    func_t *pfn = get_func(cmd.ea);
    if ( pfn != NULL )
    {
      if ( (pfn->flags & FUNC_USERFAR) == 0
        && (pfn->flags & FUNC_FAR) == 0
        && is_far_ending() )
      {
        pfn->flags |= FUNC_FAR;
        update_func(pfn);
        reanalyze_callers(pfn->startEA, 0);
      }
      if ( !flow )
        recalc_spd(cmd.ea);     // recalculate SP register for the next insn
      else
        trace_sp();
    }
  }

  if ( flow )
    ua_add_cref(0, cmd.ea+cmd.size, fl_F);

  return 1;
}

//----------------------------------------------------------------------
int is_jump_func(const func_t * /*pfn*/, ea_t *jump_target)
{
  *jump_target = BADADDR;
  return 1; // means "no"
}

//----------------------------------------------------------------------
int may_be_func(void)           // can a function start here?
                                // arg: none, the instruction is in 'cmd'
                                // returns: probability 0..100
                                // 'cmd' structure is filled upon the entrace
                                // the idp module is allowed to modify 'cmd'
{
//  if ( cmd.itype == H8_push && isbp(cmd.Op1.reg) ) return 100;  // push.l er6
  return 0;
}

//----------------------------------------------------------------------
int is_sane_insn(int /*nocrefs*/)
{
  if ( cmd.itype == H8500_nop )
  {
    for ( int i=0; i < 8; i++ )
      if ( get_word(cmd.ea-i*2) != 0 ) return 1;
    return 0; // too many nops in a row
  }
  return 1;
}

//----------------------------------------------------------------------
int idaapi is_align_insn(ea_t ea)
{
  if ( !decode_insn(ea) ) return 0;
  switch ( cmd.itype )
  {
    case H8500_nop:
      break;
    case H8500_mov_g:         // B/W Move data
    case H8500_mov_e:         // B   Move data
    case H8500_mov_i:         // W   Move data
    case H8500_mov_f:         // B/W Move data
    case H8500_mov_l:         // B/W Move data
    case H8500_mov_s:         // B/W Move data
    case H8500_or:
    case H8500_and:
      if ( cmd.Op1.type == cmd.Op2.type && cmd.Op1.reg == cmd.Op2.reg ) break;
    default:
      return 0;
  }
  return cmd.size;
}

//----------------------------------------------------------------------
int idaapi h8500_get_frame_retsize(func_t *pfn)
{
  return pfn->flags & FUNC_FAR ? 4 : 2;
}

//----------------------------------------------------------------------
static uval_t find_ret_purged(func_t *pfn)
{
  uval_t argsize = 0;
  ea_t ea = pfn->startEA;
  while ( ea < pfn->endEA )
  {
    decode_insn(ea);
    if ( cmd.itype == H8500_rtd || cmd.itype == H8500_prtd )
    {
      argsize = cmd.Op1.value;
      break;
    }
    ea = nextthat(ea, pfn->endEA, f_isCode, NULL);
  }

  // could not find any ret instructions
  // but the function ends with a jump
  if ( ea >= pfn->endEA
    && (cmd.itype == H8500_jmp || cmd.itype == H8500_pjmp) )
  {
    ea_t target = calc_mem(cmd.Op1);
    func_t *pfn = get_func(target);
    if ( pfn != NULL )
      argsize = pfn->argsize;
  }

  return argsize;
}

//----------------------------------------------------------------------
static void setup_far_func(func_t *pfn)
{
  if ( (pfn->flags & FUNC_FAR) == 0 )
  {
    ea_t ea1 = pfn->startEA;
    ea_t ea2 = pfn->endEA;
    while ( ea1 < ea2 )
    {
      if ( isCode(get_flags_novalue(ea1)) )
      {
        decode_insn(ea1);
        if ( is_far_ending() )
        {
          pfn->flags |= FUNC_FAR;
          update_func(pfn);
          break;
        }
      }
      ea1 = next_head(ea1, ea2);
    }
  }
}

//----------------------------------------------------------------------
bool idaapi create_func_frame(func_t *pfn)
{
  if ( pfn != NULL )
  {
    setup_far_func(pfn);
    uval_t argsize = find_ret_purged(pfn);
    add_frame(pfn, 0, 0, argsize);
  }
  return true;
}
