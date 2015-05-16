/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 *      16.11.95 - MAR * generated unneeded xref.
 *
 */

#include "tms.hpp"

static int flow;
//------------------------------------------------------------------------
static void doImmdValue(void) {
    doImmd(cmd.ea);
    switch ( cmd.itype ) {
        case TMS_and:
        case TMS_bit:
        case TMS_bitt:
        case TMS_bsar:
        case TMS_cmpr:
        case TMS_in:
        case TMS_intr:
        case TMS_apl2:
        case TMS_opl2:
        case TMS_xpl2:
        case TMS_or:
        case TMS_rpt:
        case TMS_xc:
        case TMS_xor:
        case TMS_rptz:

        case TMS2_bit:
        case TMS2_in:
        case TMS2_out:
        case TMS2_andk:
        case TMS2_ork:
        case TMS2_xork:
        case TMS2_rptk:
          op_num(cmd.ea,0);
    }
}

//----------------------------------------------------------------------
int find_ar(ea_t *res)
{
  ea_t ea = cmd.ea;
  for ( int i=0; i < lookback; i++ )
  {
    ea = prevInstruction(ea);
    if ( !isCode(get_flags_novalue(ea)) ) break;
    ushort code = (ushort)get_full_byte(ea);
    if ( isC2() )
    {
      switch ( code >> 11 )
      {
        case 6:                 // LAR
          return 0;
        case 0x18:              // LARK
          *res = toEA(dataSeg(),(code & 0xFF));
          return 1;
        case 0x1A:              // LRLK
          if ( (code & 0xF8FF) == 0xD000 )
          {
            ushort b = (ushort)get_full_byte(ea+1);
            *res = toEA(dataSeg(), b);
            return 1;
          }
      }
      continue;
    }
    switch ( code >> 11 )
    {
      case 0:                   // Load AR from addressed data
        return 0;               // LAR found, unknown address
      case 0x16:                // Load AR short immediate
        *res = toEA(dataSeg(), code & 0xFF);
        return 1;
      case 0x17:                // Load AR long immediate
        if ( (code & ~7) == 0xBF08 )
        {
          ushort b = (ushort)get_full_byte(ea+1);
          *res = toEA(dataSeg(),b);
          return 1;
        }
    }
  }
  return 0;
}

//----------------------------------------------------------------------
static void TouchArg(op_t &x,int isload)
{
  ea_t ea;
  switch ( x.type )
  {
  case o_phrase:                // 2 registers or indirect addressing
    if ( cmd.itype != TMS_mar && cmd.itype != TMS2_mar
                && find_ar(&ea) ) goto set_dref;
  case o_reg:
  case o_bit:
  case o_cond:
    break;
  case o_imm:
    if ( ! isload ) goto badTouch;
    doImmdValue();
    if ( isOff(uFlag, x.n) )
      ua_add_off_drefs2(x, dr_O, is_mpy() ? OOF_SIGNED : 0);
    break;
  case o_mem:
    ea = toEA(dataSeg_op(x.n),x.addr);
set_dref:
    ua_dodata2(x.offb, ea, x.dtyp);
    if ( ! isload )
      doVar(ea);
    ua_add_dref(x.offb,ea,isload ? dr_R : dr_W);
    if ( x.type == o_mem )
      if ( cmd.itype == TMS_dmov  ||
           cmd.itype == TMS_ltd   ||
           cmd.itype == TMS_macd  ||
           cmd.itype == TMS_madd  ||
           cmd.itype == TMS2_dmov ||
           cmd.itype == TMS2_macd  ) ua_add_dref(x.offb,ea+1,dr_W);
    break;
  case o_near:
    {
      ea_t segbase = codeSeg(x.addr, x.n);
      ea = toEA(segbase, x.addr);
      if ( cmd.itype == TMS_blpd ||
           cmd.itype == TMS_mac  ||
           cmd.itype == TMS_macd ||
           cmd.itype == TMS2_blkp ||
           cmd.itype == TMS2_mac  ||
           cmd.itype == TMS2_macd
         ) goto set_dref;
      uval_t thisseg = cmd.cs;
      int iscall = InstrIsSet(cmd.itype,CF_CALL);
      if ( cmd.itype == TMS_rptb && isTail(get_flags_novalue(ea)) )
      {
        // small hack to display end_loop-1 instead of before_end_loop+1
        ea++;
      }

      ua_add_cref(x.offb,
                  ea,
                  iscall ? ((segbase == thisseg) ? fl_CN : fl_CF)
                         : ((segbase == thisseg) ? fl_JN : fl_JF));
      if ( iscall )
      {
        if ( !func_does_return(ea) )
          flow = false;
      }
    }
    break;
  default:
badTouch:
    warning("%a: %s,%d: bad optype %d", cmd.ea, cmd.get_canon_mnem(), x.n, x.type);
    break;
  }
}

//----------------------------------------------------------------------
static int isDelayedStop(ushort code)
{
  switch ( code>>12 )
  {
    case 7:
      return (code & 0xFF00u) == 0x7D00u;
    case 0xB:
      return code == 0xBE21u;
    case 0xF:
      return (code & 0xEFFFu) == 0xEF00u;
  }
  return 0;
}

//----------------------------------------------------------------------
static int canFlow(void)
{
  if ( isC2() ) return 1;
  if ( !isFlow(uFlag) ) return 1;               // no previous instructions
  ea_t ea = prevInstruction(cmd.ea);
  if ( cmd.size == 2 )                          // our instruction is long
  {
    ; // nothing to do
  }
  else
  {                                             // our instruction short
    if ( (cmd.ea-ea) == 2 )                     // prev instruction long
      return 1;                                 // can flow always
    flags_t F = get_flags_novalue(ea);
    if ( !isCode(F) || !isFlow(F) ) return 1;   // no prev instr...
    ea = prevInstruction(ea);
  }
  flags_t F = get_flags_novalue(ea);
  return !isCode(F) || !isDelayedStop((ushort)get_full_byte(ea));
}

//----------------------------------------------------------------------
int idaapi emu(void)
{
  uint32 Feature = cmd.get_canon_feature();
  flow = ((Feature & CF_STOP) == 0);

  if ( Feature & CF_USE1 ) TouchArg(cmd.Op1,1);
  if ( Feature & CF_USE2 ) TouchArg(cmd.Op2,1);
  if ( Feature & CF_JUMP ) QueueMark(Q_jumps,cmd.ea);

  if ( Feature & CF_CHG1 ) TouchArg(cmd.Op1,0);
  if ( Feature & CF_CHG2 ) TouchArg(cmd.Op2,0);

  if ( flow && canFlow() ) ua_add_cref(0,cmd.ea+cmd.size,fl_F);

  switch ( cmd.itype )
  {
    case TMS_ldp:                       // change DP register
    case TMS2_ldp:                      // change DP register
    case TMS2_ldpk:                     // change DP register
      {
        uint v = (cmd.Op1.type == o_imm) ? uint(cmd.Op1.value) : -1u;
        splitSRarea1(get_item_end(cmd.ea),rDP,v,SR_auto);
      }
      break;
  }

  return 1;
}
