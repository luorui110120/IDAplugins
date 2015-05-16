/*
 *      Interactive disassembler (IDA).
 *      Version 3.06
 *      Copyright (c) 1990-96 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "i5.hpp"

//----------------------------------------------------------------------

//static WorkReg R1,R2;   // emulator registers
static int flow;

//------------------------------------------------------------------------
static void doImmdValue(int n)
{
  doImmd(cmd.ea);
  if ( !isDefArg(uFlag, n) )
  {
    switch ( cmd.itype )
    {
      case I5_ani:
      case I5_xri:
      case I5_ori:
      case I5_in:
      case I5_out:
      case I5_rst:

      case HD_in0:
      case HD_out0:
      case HD_tstio:
        op_num(cmd.ea,-1);
        break;
    }
  }
}

//----------------------------------------------------------------------
static int LoadArg(op_t &x)
{
  dref_t xreftype;
  switch ( x.type ) {
  case o_reg:
    {
      if ( x.reg == R_sp ) goto Undefined;
//      AbstractRegister *in = &i5_getreg(x.reg);
//      if ( ! in->isDef() ) goto Undefined;
//      r.doInt(in->value());
      return 1;
    }
  case o_imm:
//    r.doInt(unsigned(x.value));
    xreftype = dr_O;
MakeImm:
    doImmdValue(x.n);
    if ( isOff(uFlag, x.n) )
      ua_add_off_drefs2(x, xreftype, 0);
    return 1;
  case o_displ:
//    r.undef();
    xreftype = dr_R;
    goto MakeImm;
  case o_mem:
    {
      ea_t ea = toEA(dataSeg_op(x.n),x.addr);
      ua_add_dref(x.offb,ea,dr_R);
      ua_dodata2(x.offb, ea, x.dtyp);
      if ( !isVar(get_flags_novalue(ea)) && isLoaded(ea) )
      {
//        r.doInt( x.dtyp != dt_byte ? get_word(ea) : char(get_byte(ea)) );
        return 1;
      }
    }
  case o_phrase:
Undefined:
//    r.undef();
    break;

  case o_near:
    {
      ea_t segbase = codeSeg(x.addr,x.n);
      ea_t ea = toEA(segbase,x.addr);
      ea_t thisseg = cmd.cs;
      int iscall = InstrIsSet(cmd.itype,CF_CALL);
      ua_add_cref(x.offb,
                  ea,
                  iscall ? ((segbase == thisseg) ? fl_CN : fl_CF)
                         : ((segbase == thisseg) ? fl_JN : fl_JF));
      if ( iscall && !func_does_return(ea) )
        flow = false;
//      r.doInt(unsigned(x.addr));
    }
    return 1;
  default:
//  warning("%a: %s,%d: bad load optype %d", cmd.ea, cmd.get_canon_mnem(), x.n, x.type);
    break;
  }
  return 0;
}

//----------------------------------------------------------------------
static void SaveArg(op_t &x)
{
  switch ( x.type )
  {
    case o_reg:
      {
//        if ( x.reg == R_sp ) return;
//        AbstractRegister *out = &i5_getreg(x.reg);
//        if ( ! isDef(r) ) {
//          out->undef();
//        } else {
//          out->doInt(r.value());
//        }
        return;
      }
    case o_mem:
      {
        ea_t ea = toEA(dataSeg_op(x.n),x.addr);
        ua_dodata2(x.offb, ea, x.dtyp);
        doVar(ea);
        ua_add_dref(x.offb,ea,dr_W);
      }
      break;
    case o_displ:
      doImmdValue(x.n);
      if ( isOff(uFlag, x.n) )
        ua_add_off_drefs2(x, dr_W, OOF_ADDR);
    case o_phrase:
      break;
    default:
      switch ( cmd.itype )
      {
        case Z80_in0:
        case Z80_outaw:
          break;
        default:
//        warning("%a: %s,%d: bad save optype %d", cmd.ea, cmd.get_canon_mnem(), x.n, x.type);
          break;
      }
      break;
  }
}

//----------------------------------------------------------------------
int idaapi i5_emu(void) {

  uint32 Feature = cmd.get_canon_feature();
  flow = ((Feature & CF_STOP) == 0);

  if ( (Feature & CF_USE1) ) LoadArg(cmd.Op1);
  if ( (Feature & CF_USE2) ) LoadArg(cmd.Op2);

  if ( Feature & CF_JUMP ) QueueMark(Q_jumps,cmd.ea);


  switch ( cmd.itype )
  {
    case I5_mov:
    case I5_mvi:
    case Z80_ld:
//        if ( ! fail ) R1.doInt( R2.value() );
//        else R1.undef();
        break;
    case Z80_jp:
    case Z80_jr:                // Z80
    case Z80_ret:               // Z80
        if ( cmd.Op1.Cond != oc_not ) break;
    case I5_jmp:
        if ( cmd.Op2.type == o_phrase ) QueueMark(Q_jumps,cmd.ea);
    case I5_ret:
        flow = 0;
        break;
    case I5_rstv:
        ua_add_cref(0,toEA(codeSeg(0x40,0),0x40),fl_CN);
        break;
    case I5_rst:
        {
          int mul = (isZ80() ? 1 : 8);
          ushort offset = ushort(cmd.Op1.value * mul);
          ua_add_cref(0,toEA(codeSeg(offset,0),offset),fl_CN);
        }
    case I5_call:
    case I5_cc:
    case I5_cnc:
    case I5_cz:
    case I5_cnz:
    case I5_cpe:
    case I5_cpo:
    case I5_cp:
    case I5_cm:
    case Z80_exx:               // Z80
//        i5_CPUregs.bc.undef();
//        i5_CPUregs.de.undef();
//        i5_CPUregs.hl.undef();
//        i5_CPUregs.af.undef();
//        i5_CPUregs.ix.undef();
//        i5_CPUregs.iy.undef();
        break;
    default:
//        R1.undef();
//        R2.undef();
        break;
  }

  if ( Feature & CF_CHG1 ) SaveArg(cmd.Op1);
  if ( Feature & CF_CHG2 ) SaveArg(cmd.Op2);

  if ( flow ) ua_add_cref(0,cmd.ea+cmd.size,fl_F);

  return 1;
}
