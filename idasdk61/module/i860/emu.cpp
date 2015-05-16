/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "i860.hpp"

//------------------------------------------------------------------------
static void doImmdValue(void)
{
  doImmd(cmd.ea);
  switch ( cmd.itype )
  {
    case I860_and:
    case I860_andh:
    case I860_andnot:
    case I860_andnoth:
    case I860_xor:
    case I860_xorh:
      op_num(cmd.ea,1);
      break;
  }
}

//----------------------------------------------------------------------
static bool TouchArg(op_t &x,int isload)
{
  dref_t xreftype;
  uchar outf;
  switch ( x.type )
  {
  case o_phrase:                // 2 registers
  case o_reg:
    break;
  case o_imm:
    if ( ! isload ) goto badTouch;
    xreftype = dr_O;
    outf = OOF_SIGNED;
    goto makeImm;
  case o_displ:
    xreftype = isload ? dr_R : dr_W;
    outf = OOF_SIGNED|OOF_ADDR;
makeImm:
    doImmdValue();
    if ( isOff(uFlag, x.n) )
      ua_add_off_drefs2(x, xreftype, outf);
    break;
  case o_mem:
    ua_dodata2(x.offb, x.addr, x.dtyp);
    if ( !isload )
      doVar(x.addr);
    ua_add_dref(x.offb,x.addr,isload ? dr_R : dr_W);
    break;
  case o_near:
    {
      int iscall = InstrIsSet(cmd.itype,CF_CALL);
      ua_add_cref(x.offb,x.addr,iscall ? fl_CN : fl_JN);
      if ( iscall && !func_does_return(x.addr) )
        return false;
    }
    break;
  default:
badTouch:
    warning("%a: %s,%d: bad optype %d", cmd.ea, cmd.get_canon_mnem(), x.n, x.type);
    break;
  }
  return true;
}

//----------------------------------------------------------------------
static bool isDual(uint32 code)
{
  return int(code>>26) == 0x12 && (code & Dbit) != 0;
}

//----------------------------------------------------------------------
//static int isDelayed(uint32 code) {
//                      // bc.t bla bnc.t br bri call calli
//  int opcode = int(code >> 26);
//  switch ( opcode ) {
//    case 0x13:
//      return ((code & 0x1F) == 2);    // calli
//    case 0x10:                // bri
//    case 0x1A:                // br
//    case 0x1B:                // call
//    case 0x1D:                // bc.t
//    case 0x1F:                // bnc.t
//    case 0x2D:                // bla
//      return 1;
//  }
//  return 0;
//}
//
//----------------------------------------------------------------------
static int isDelayedStop(uint32 code)
{
                        // br bri
  int opcode = int(code >> 26);
  switch ( opcode ) {
    case 0x10:          // bri
    case 0x1A:          // br
      return 1;
  }
  return 0;
}

//----------------------------------------------------------------------
static bool canFlow(void)
{
  if ( ! isFlow(uFlag) ) return 1;             // no previous instructions
  ea_t ea = cmd.ea - 4;
  flags_t F = get_flags_novalue(ea);
  if ( isFlow(F) && isCode(F) )
  {
    if ( isDelayedStop(get_long(ea)) )         // now or later
    {
      ea -= 4;
      if ( !isCode(get_flags_novalue(ea)) || !isDual(get_long(ea)) ) return 0;
      return 1;
    }
    if ( isFlow(F) )
    {
      ea -= 4;
      return !isCode(get_flags_novalue(ea)) || !isDelayedStop(get_long(ea));
    }
  }
  return 1;
}

//----------------------------------------------------------------------
int idaapi i860_emu(void)
{
  bool funcret = true;

  uint32 Feature = cmd.get_canon_feature();

  if ( Feature & CF_USE1 ) if ( !TouchArg(cmd.Op1,1) ) funcret = false;
  if ( Feature & CF_USE2 ) if ( !TouchArg(cmd.Op2,1) ) funcret = false;
  if ( Feature & CF_USE3 ) if ( !TouchArg(cmd.Op3,1) ) funcret = false;
  if ( Feature & CF_JUMP ) QueueMark(Q_jumps,cmd.ea);

  if ( Feature & CF_CHG1 ) if ( !TouchArg(cmd.Op1,0) ) funcret = false;
  if ( Feature & CF_CHG2 ) if ( !TouchArg(cmd.Op2,0) ) funcret = false;
  if ( Feature & CF_CHG3 ) if ( !TouchArg(cmd.Op3,0) ) funcret = false;

  if ( funcret && canFlow() ) ua_add_cref(0,cmd.ea+cmd.size,fl_F);
  return 1;
}
