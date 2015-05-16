/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Processor emulator
 *
 */
#include <ida.hpp>
#include <auto.hpp>
#include <frame.hpp>
#include <queue.hpp>
#include "ins.hpp"
#include "necv850.hpp"

//----------------------------------------------------------------------
//#notify.is_sane_insn
// is the instruction sane for the current file type?
// arg:  int no_crefs
// 1: the instruction has no code refs to it.
//    ida just tries to convert unexplored bytes
//    to an instruction (but there is no other
//    reason to convert them into an instruction)
// 0: the instruction is created because
//    of some coderef, user request or another
//    weighty reason.
// The instruction is in 'cmd'
// returns: 1-ok, <=0-no, the instruction isn't likely to appear in the program
int nec850_is_sane_insn(int /*no_crefs*/)
{
#define CHECK_R0_WRITE(n) \
  if ( ((Feature & CF_CHG ## n) != 0)  \
    && cmd.Op ## n.is_reg(rZERO) )  \
  { \
      return 0; \
  }
  int Feature = cmd.get_canon_feature();

  CHECK_R0_WRITE(1);
  CHECK_R0_WRITE(2);
  return 1;
}

//----------------------------------------------------------------------
// return number of set bits
static int bitcount(uint32 w)
{
  uint32 allones = ~0;
  uint32 mask1h = allones / 3 << 1;
  uint32 mask2l = allones / 5;
  uint32 mask4l = allones / 17;
  w -= (mask1h & w) >> 1;
  w = (w & mask2l) + ((w>>2) & mask2l);
  w = (w + (w >> 4)) & mask4l;
  w += w >> 8;
  w += w >> 16;
  return w & 0xff;
}

//----------------------------------------------------------------------
int idaapi nec850_is_sp_based(const op_t &x)
{
  return OP_SP_ADD | ((x.type == o_displ && x.reg == rSP) ? OP_SP_BASED : OP_FP_BASED);
}

//----------------------------------------------------------------------
bool idaapi nec850_create_func_frame(func_t *pfn)
{
  asize_t frsize;

  if ( (decode_insn(pfn->startEA) != BADADDR)
    && (cmd.itype == NEC850_PREPARE_i || cmd.itype == NEC850_PREPARE_sp) )
  {
    frsize = cmd.Op2.value * 4;
  }
  else
  {
    frsize = 0;
  }
  return add_frame(pfn, frsize, 0, 0);
}

//----------------------------------------------------------------------
int idaapi nec850_get_frame_retsize(func_t * /*pfn*/)
{
  return 0;
}

//----------------------------------------------------------------------
// the pattern is as follows
// ----------------------------
// optional:
//             movea   -first_case, reg, switch_reg
//   or
//             add     -first_case, switch_reg
//

// then

//             cmp     nb_cases, switch_reg
// or
//             cmp     nb_cases, copy_switch_reg
//             mov     copy_switch_reg, switch_reg

// then

// EB 1D       bh      default_location
// 4A 00       switch  switch_reg
static bool is_switch_idiom1(switch_info_ex_t *si)
{
  if ( cmd.itype != NEC850_SWITCH )
    return false;

  // save switch register
  uint16 switch_reg = cmd.Op1.reg;

  // not really a switch
  if ( switch_reg == rZERO )
    return false;

  // address of jump table directly after the instruction
  si->jumps    = cmd.ea + cmd.size;
  si->startea  = cmd.ea;
  si->flags    = SWI_EXTENDED | SWI_DEFAULT;

  // decode and see if we have a branch
  if ( (decode_prev_insn(cmd.ea) == BADADDR) || ((cmd.auxpref & N850F_ADDR_OP1) == 0) )
      return false;

  // the default case
  si->defjump = cmd.Op1.addr;

  // decode the instruction; we expect at this point either a MOV or a CMP
  if ( decode_prev_insn(cmd.ea) == BADADDR )
    return false;

  uint16 copy_switch_reg = switch_reg;

  // it's a MOV?
  if ( cmd.itype == NEC850_MOV )
  {
    // MOV copy_switch_reg, switch_reg
    if ( cmd.Op2.reg != switch_reg )
      return false;
    // okay, now we will look next for
    //   CMP ncases, copy_switch_reg
    // instead of
    //   CMP ncases, switch_reg
    copy_switch_reg = cmd.Op1.reg;

    if ( decode_prev_insn(cmd.ea) == BADADDR )
      return false;
  }

  if ( (cmd.itype != NEC850_CMP) || (cmd.Op2.reg != copy_switch_reg) )
    return false;

  // CMP ncases, switch_reg
  si->ncases  = cmd.Op1.value+1;

  // we can also try to detect the first index of the case
  // (this is could be through a MOVEA or ADD
  if ( decode_prev_insn(cmd.ea) != BADADDR )
  {
    // MOVEA -first_case, reg, switch_reg
    if ( (cmd.itype == NEC850_MOVEA) && (cmd.Op3.reg == switch_reg) )
      si->lowcase = uval_t(-uint32(cmd.Op1.value));
    // ADD -first_case_imm, switch_reg
    else if ( (cmd.itype == NEC850_ADD)
      && (cmd.Op1.type == o_imm)
      && (cmd.Op2.reg == switch_reg) )
    {
      si->lowcase = uval_t(-uint32(cmd.Op1.value));
    }
  }

  si->flags2  = 0;
  si->elbase  = 0;
  si->set_jtable_element_size(2);
  si->set_shift(1);
  si->set_expr(switch_reg, dt_dword);

  return true;
}

//----------------------------------------------------------------------
bool idaapi nec850_is_switch(switch_info_ex_t *si)
{
  return is_switch_idiom1(si);
}

//----------------------------------------------------------------------
static void TouchArg(op_t &op, int isRead)
{
  switch ( op.type )
  {
  case o_imm:
    if ( isOff(uFlag, op.n) )
      ua_add_off_drefs(op, dr_O);
    break;
  case o_displ:
    // create data xrefs
    if ( isOff(uFlag, op.n) )
      ua_add_off_drefs(op, isRead ? dr_R : dr_W);
    // create local variables
    else if ( may_create_stkvars()
      && !isDefArg(uFlag, op.n)
      && op.reg == rSP )
    {
      func_t *pfn = get_func(cmd.ea);
      if ( pfn != NULL  )
      {
        if ( ua_stkvar2(op, op.addr, STKVAR_VALID_SIZE) )
          op_stkvar(cmd.ea, op.n);
      }
    }
    break;
  case o_mem:
    ua_add_dref(op.offb, op.addr, isRead ? dr_R : dr_W);
    break;
  }
}

//----------------------------------------------------------------------
static void idaapi trace_stack(func_t *pfn)
{
  sval_t delta;
  switch ( cmd.itype )
  {
  case NEC850_PREPARE_i:
  case NEC850_PREPARE_sp:
    {
      insn_t saved_cmd = cmd;
      delta  = -((bitcount(cmd.Op1.value) * 4) + (cmd.Op2.value << 2));

      // PATTERN #1
      /*
      00000030     _func3:
      00000030 000                 br      loc_5E
      00000032
      00000032     loc_32:                                 -- CODE XREF: _func3+32j
      00000032 000                 st.w    r6, 4[sp]
      0000005A
      0000005A     loc_5A:                                 -- CODE XREF: _func3+10j
      0000005A                                             -- _func3+14j ...
      0000005A 000                 dispose 2, {lp}, [lp]
      0000005E     -- ---------------------------------------------------------------------------
      0000005E
      0000005E     loc_5E:                                 -- CODE XREF: _func3
      0000005E -0C                 prepare {lp}, 2
      00000062 000                 br      loc_32
      00000062     -- End of function _func3
      */
      bool farref;
      if ( decode_preceding_insn(cmd.ea, &farref) != BADADDR
        && ( (cmd.itype == NEC850_BR) || (cmd.itype == NEC850_JR) ) )
      {
        add_auto_stkpnt2(pfn, cmd.ea + cmd.size, delta);
      }

      cmd = saved_cmd;
    }
    break;
  case NEC850_DISPOSE_r:
  case NEC850_DISPOSE_r0:
    // count registers in LIST12 and use the imm5 for local vars
    delta  = (bitcount(cmd.Op2.value) * 4) + (cmd.Op1.value << 2);
    break;
  case NEC850_ADD:
  case NEC850_ADDI:
  case NEC850_MOVEA:
    delta = cmd.Op1.value;
    break;
  default:
    return;
  }
  add_auto_stkpnt2(pfn, cmd.ea + cmd.size, delta);
}

//----------------------------------------------------------------------
int idaapi nec850_emu(void)
{
  op_t *op;
  int aux = cmd.auxpref;
  if ( aux & N850F_ADDR_OP1 )
     op = &cmd.Op1;
  else if ( aux & N850F_ADDR_OP2 )
    op = &cmd.Op2;
  else
    op = NULL;

  int Feature = cmd.get_canon_feature();

  if ( Feature & CF_USE1 ) TouchArg(cmd.Op1, 1);
  if ( Feature & CF_CHG1 ) TouchArg(cmd.Op1, 0);
  if ( Feature & CF_USE2 ) TouchArg(cmd.Op2, 1);
  if ( Feature & CF_CHG2 ) TouchArg(cmd.Op2, 0);
  if ( Feature & CF_USE3 ) TouchArg(cmd.Op3, 1);
  if ( Feature & CF_CHG3 ) TouchArg(cmd.Op3, 0);
  if ( Feature & CF_JUMP ) QueueMark(Q_jumps, cmd.ea);

  // add jump or call ( type = o_near )
  if ( op != NULL )
    ua_add_cref(op->offb, op->addr, (aux & N850F_CALL) == 0 ? fl_JN : fl_CN);

  if ( (aux & N850F_SP) && may_trace_sp() )
  {
    func_t *pfn = get_func(cmd.ea);
    if ( pfn != NULL )
      trace_stack(pfn);
  }
  // add flow
  if ( (Feature & CF_STOP) == 0 )
     ua_add_cref(0, cmd.ea + cmd.size, fl_F);

  return 1;
}

//----------------------------------------------------------------------
