/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "st20.hpp"

static bool flow;
//------------------------------------------------------------------------
static void process_immediate_number(int n)
{
  doImmd(cmd.ea);
  if ( isDefArg(uFlag,n) ) return;
  switch ( cmd.itype )
  {
    case ST20_ajw:
      op_num(cmd.ea, n);
      break;
  }
}

//----------------------------------------------------------------------
ea_t calc_mem(ea_t ea)
{
  return toEA(cmd.cs, ea);
}

//----------------------------------------------------------------------
static void process_operand(op_t &x,int /*isAlt*/,int isload)
{
  ea_t ea;
  switch ( x.type )
  {
    case o_imm:
      if ( !isload ) interr("emu");
      process_immediate_number(x.n);
      if ( isOff(uFlag, x.n) )
        ua_add_off_drefs2(x, dr_O, 0);
      break;
    case o_near:
      {
        cref_t ftype = fl_JN;
        ea = calc_mem(x.addr);
        if ( InstrIsSet(cmd.itype, CF_CALL) )
        {
          if ( !func_does_return(ea) )
            flow = false;
          ftype = fl_CN;
        }
        ua_add_cref(x.offb, ea, ftype);
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
  int flag1 = is_forced_operand(cmd.ea, 0);

  flow = ((Feature & CF_STOP) == 0);

  if ( Feature & CF_USE1 ) process_operand(cmd.Op1, flag1, 1);
  if ( Feature & CF_CHG1 ) process_operand(cmd.Op1, flag1, 0);

//
//      Determine if the next instruction should be executed
//
  if ( segtype(cmd.ea) == SEG_XTRN ) flow = 0;
  if ( flow ) ua_add_cref(0,cmd.ea+cmd.size,fl_F);

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
  if ( cmd.itype == ST20_nop )
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
    case ST20_nop:
      break;
    default:
      return 0;
  }
  return cmd.size;
}

