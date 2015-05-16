/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *      Atmel AVR - 8-bit RISC processor
 *
 */

#include "avr.hpp"

static int flow;
//------------------------------------------------------------------------
static void doImmdValue(int n)
{
  doImmd(cmd.ea);
  if ( isDefArg(uFlag,n) ) return;
  switch ( cmd.itype )
  {
    case AVR_andi:
    case AVR_ori:
      op_num(cmd.ea, n);
  }
}

//----------------------------------------------------------------------
static void TouchArg(op_t &x,int isAlt,int isload)
{
  switch ( x.type )
  {
    case o_reg:
    case o_phrase:
    case o_port:
      break;
    case o_imm:
      if ( !isload ) goto badTouch;
      doImmdValue(x.n);
      if ( isOff(uFlag, x.n) )
        ua_add_off_drefs2(x, dr_O, OOF_SIGNED);
      break;
    case o_displ:
      doImmdValue(x.n);
      if ( isAlt ) break;
      if ( isOff(uFlag, x.n) )
      {
        ua_add_off_drefs2(x, isload ? dr_R : dr_W, OOF_ADDR);
        ea_t ea = calc_target(cmd.ea+x.offb, cmd.ea, x.n, x.addr);
        ua_dodata2(x.offb, ea, x.dtyp);
        if ( !isload )
          doVar(ea);
      }
      break;
    case o_near:
      {
        cref_t ftype = fl_JN;
        ea_t ea = toEA(cmd.cs, x.addr);
        if ( InstrIsSet(cmd.itype, CF_CALL) )
        {
          if ( !func_does_return(ea) )
            flow = false;
          ftype = fl_CN;
        }
        ua_add_cref(x.offb, ea, ftype);
      }
      break;
    case o_mem:
      {
        ea_t ea = toEA(dataSeg(), x.addr);
        ua_add_dref(x.offb, ea, isload ? dr_R : dr_W);
      }
      break;
    default:
badTouch:
      if ( cmd.itype != AVR_lpm && cmd.itype != AVR_elpm )
        warning("%a: %s,%d: bad optype %d", cmd.ea, cmd.get_canon_mnem(), x.n, x.type);
      break;
  }
}

//----------------------------------------------------------------------
static bool may_be_skipped(void)
{
  ea_t ea = cmd.ea - 1;
  if ( isCode(get_flags_novalue(ea)) )
  {
    int code = get_full_byte(ea);
    switch ( code & 0xFC00 )
    {
// 0001 00rd dddd rrrr     cpse    rd, rr  4  Compare, Skip if Equal
      case 0x1000:
// 1111 110r rrrr xbbb     sbrc    rr, b      Skip if Bit in I/O Register Cleared
// 1111 111r rrrr xbbb     sbrs    rr, b      Skip if Bit in I/O Register Set
      case 0xFC00:
        return true;
// 1001 1001 pppp pbbb     sbic    p, b       Skip if Bit in Register Cleared
// 1001 1011 pppp pbbb     sbis    p, b       Skip if Bit in Register Set
      case 0x9800:
        return (code & 0x0100) != 0;
    }
  }
  return false;
}

//----------------------------------------------------------------------
int idaapi emu(void)
{
  uint32 Feature = cmd.get_canon_feature();
  int flag1 = is_forced_operand(cmd.ea, 0);
  int flag2 = is_forced_operand(cmd.ea, 1);
  int flag3 = is_forced_operand(cmd.ea, 2);

  flow = ((Feature & CF_STOP) == 0);

  if ( Feature & CF_USE1 ) TouchArg(cmd.Op1, flag1, 1);
  if ( Feature & CF_USE2 ) TouchArg(cmd.Op2, flag2, 1);
  if ( Feature & CF_USE3 ) TouchArg(cmd.Op3, flag3, 1);

  if ( Feature & CF_CHG1 ) TouchArg(cmd.Op1, flag1, 0);
  if ( Feature & CF_CHG2 ) TouchArg(cmd.Op2, flag2, 0);
  if ( Feature & CF_CHG3 ) TouchArg(cmd.Op3, flag3, 0);

//
//      Determine if the next instruction should be executed
//
  if ( !flow ) flow = may_be_skipped();
  if ( segtype(cmd.ea) == SEG_XTRN ) flow = 0;
  if ( flow ) ua_add_cref(0,cmd.ea+cmd.size,fl_F);

  return 1;
}

//----------------------------------------------------------------------
int idaapi is_align_insn(ea_t ea)
{
  decode_insn(ea);
  switch ( cmd.itype ) {
    case AVR_mov:
      if ( cmd.Op1.reg == cmd.Op2.reg ) break;
    default:
      return 0;
    case AVR_nop:
      break;
  }
  return cmd.size;
}
