/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "i960.hpp"

static bool flow;
//------------------------------------------------------------------------
static void process_immediate_number(int n)
{
  doImmd(cmd.ea);
  if ( isDefArg(uFlag,n) ) return;
/*  switch ( cmd.itype )
  {
      op_dec(cmd.ea, n);
      break;
  }*/
}

//----------------------------------------------------------------------
ea_t calc_mem(ea_t ea)
{
  return toEA(cmd.cs, ea);
}

//----------------------------------------------------------------------
static void process_operand(op_t &x, bool isload)
{
  ea_t ea;
  dref_t dref;
  if ( is_forced_operand(cmd.ea, x.n) ) return;
  switch ( x.type )
  {
    case o_reg:
    case o_phrase:
      break;

    case o_imm:
      if ( !isload ) interr("emu1");
      process_immediate_number(x.n);
      if ( isOff(uFlag, x.n) )
        ua_add_off_drefs2(x, dr_O, OOFS_IFSIGN|OOFW_IMM);
      break;

    case o_mem:
      ea = calc_mem(x.addr);
      ua_dodata2(x.offb, ea, x.dtyp);
      dref = cmd.itype == I960_lda ? dr_O : isload ? dr_R : dr_W;
      ua_add_dref(x.offb, ea, dref);
      break;

    case o_near:
      {
        cref_t ftype = fl_JN;
        ea = calc_mem(x.addr);
        if ( InstrIsSet(cmd.itype, CF_CALL) )
        {
          flow = func_does_return(ea);
          ftype = fl_CN;
        }
        ua_add_cref(x.offb, ea, ftype);
      }
      break;

    case o_displ:
      dref = cmd.itype == I960_lda ? dr_O : isload ? dr_R : dr_W;
      process_immediate_number(x.n);
      if ( x.reg == IP )
      {
        ea_t ea = cmd.ea + 8 + x.addr;
        ua_add_dref(x.offb, ea, dref);
      }
      else
      {
        if ( isOff(uFlag, x.n) )
          ua_add_off_drefs2(x, dref, OOFS_IFSIGN|OOF_SIGNED|OOF_ADDR|OOFW_32);
      }
      break;

    default:
      interr("emu");
  }
}


//----------------------------------------------------------------------
int idaapi emu(void)
{
  uint32 Feature = cmd.get_canon_feature();

  flow = ((Feature & CF_STOP) == 0);

  if ( Feature & CF_USE1 ) process_operand(cmd.Op1, true);
  if ( Feature & CF_USE2 ) process_operand(cmd.Op2, true);
  if ( Feature & CF_USE3 ) process_operand(cmd.Op3, true);
  if ( Feature & CF_CHG1 ) process_operand(cmd.Op1, false);
  if ( Feature & CF_CHG2 ) process_operand(cmd.Op2, false);
  if ( Feature & CF_CHG3 ) process_operand(cmd.Op3, false);

//
//      Determine if the next instruction should be executed
//
  if ( segtype(cmd.ea) == SEG_XTRN ) flow = 0;
  if ( flow ) ua_add_cref(0,cmd.ea+cmd.size,fl_F);

//
//      convert "lda imm, reg" to "lda mem, reg"
//

  if ( cmd.itype == I960_lda
    && cmd.Op1.type == o_imm
    && !isDefArg(uFlag, 0)
    && isEnabled(cmd.Op1.value) ) set_offset(cmd.ea, 0, 0);

  return 1;
}

//----------------------------------------------------------------------
int idaapi is_align_insn(ea_t /*ea*/)
{
  return false;
}
