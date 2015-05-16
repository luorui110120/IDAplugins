/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "m65.hpp"

static bool flow;
//------------------------------------------------------------------------
static void doImmdValue(void)
{
  doImmd(cmd.ea);
}

//----------------------------------------------------------------------
static void TouchArg(op_t &x,int isload)
{
  ea_t ea;
  dref_t xreftype;
  switch ( x.type )
  {
    case o_reg:
      break;
    case o_imm:
      if ( !isload ) goto badTouch;
      xreftype = dr_O;
      goto MAKE_IMMD;
    case o_displ:
      xreftype = isload ? dr_R : dr_W;
MAKE_IMMD:
      doImmdValue();
      if ( isOff(uFlag,x.n) ) ua_add_off_drefs(x, xreftype);
      break;
    case o_mem:
      ea = toEA(dataSeg_op(x.n),x.addr);
      ua_dodata2(x.offb, ea, x.dtyp);
      if ( ! isload ) doVar(ea);
      ua_add_dref(x.offb,ea,isload ? dr_R : dr_W);
      break;
    case o_near:
      {
        ea_t segbase = codeSeg(x.addr,x.n);
        ea = toEA(segbase,x.addr);
        ea_t thisseg = cmd.cs;
        int iscall = InstrIsSet(cmd.itype, CF_CALL);
        ua_add_cref(x.offb,
                    ea,
                    iscall ? ((segbase == thisseg) ? fl_CN : fl_CF)
                           : ((segbase == thisseg) ? fl_JN : fl_JF));
        if ( flow && iscall )
          flow = func_does_return(ea);
      }
      break;
    default:
badTouch:
      warning("%a: %s,%d: bad optype %d", cmd.ea, cmd.get_canon_mnem(), x.n, x.type);
      break;
  }
}

//----------------------------------------------------------------------
int idaapi emu(void)
{
  uint32 Feature = cmd.get_canon_feature();
  flow = ((Feature & CF_STOP) == 0);

  if ( Feature & CF_USE1 ) TouchArg(cmd.Op1, 1);
  if ( Feature & CF_USE2 ) TouchArg(cmd.Op2, 1);
  if ( Feature & CF_CHG1 ) TouchArg(cmd.Op1, 0);
  if ( Feature & CF_CHG2 ) TouchArg(cmd.Op2, 0);
  if ( Feature & CF_JUMP ) QueueMark(Q_jumps,cmd.ea);

  if ( flow )
    ua_add_cref(0,cmd.ea+cmd.size,fl_F);

  return 1;
}
