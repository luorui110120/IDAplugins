/*
 *  Interactive disassembler (IDA).
 *  Intel 80196 module
 *
 */

#include "i196.hpp"

static int  flow;

//----------------------------------------------------------------------
static void TouchArg( op_t &x, int isload )
{
  switch( x.type )
  {
    case o_imm:
      doImmd(cmd.ea);
      if ( isOff(uFlag, x.n) )
        ua_add_off_drefs2(x, dr_O, OOF_SIGNED);
      break;
    case o_indexed:                                 // addr[value]
      doImmd(cmd.ea);
      if ( x.value == 0 && !isDefArg(uFlag, x.n) )
        set_offset(cmd.ea, x.n, toEA(cmd.cs, 0));
      if ( isOff(uFlag, x.n) )                      // xref to addr
      {
        uval_t saved = x.value;
        x.value = x.addr;
        ua_add_off_drefs2(x, saved ? dr_O : isload ? dr_R : dr_W, OOF_SIGNED|OOF_ADDR);
        x.value = saved;
      }
      if ( x.value != 0 )                           // xref to value
      {                                             // no references to ZERO_REG
        ea_t ea = toEA(cmd.cs, x.value);
        ua_add_dref(x.offb, ea, isload ? dr_R : dr_W );
        ua_dodata2(x.offb, ea, x.dtyp);
      }
      break;
    case o_indirect:
    case o_indirect_inc:
    case o_mem:
      {
        ea_t dea = toEA( cmd.cs, x.addr );
        ua_dodata2(x.offb, dea, x.dtyp);
        if( !isload )
          doVar(dea);
        ua_add_dref( x.offb, dea, isload ? dr_R : dr_W );
        if ( !isload && (x.addr == 0x14 || x.addr == 0x15) )
        {
          sel_t wsrval = BADSEL;
          if ( cmd.Op2.type == o_imm ) wsrval = sel_t(cmd.Op2.value);
          splitSRarea1(cmd.ea, x.addr == 0x14 ? WSR : WSR1, wsrval, SR_auto);
        }
      }
      break;

    case o_near:
      ea_t ea = toEA( cmd.cs, x.addr );
      int iscall = InstrIsSet( cmd.itype, CF_CALL );
      ua_add_cref( x.offb, ea, iscall ? fl_CN : fl_JN );
      if ( flow && iscall )
        flow = func_does_return(ea);
  }
}

//----------------------------------------------------------------------

int idaapi emu( void )
{
  uint32 Feature = cmd.get_canon_feature();

  flow = ((Feature & CF_STOP) == 0);

  if( Feature & CF_USE1 )   TouchArg( cmd.Op1, 1 );
  if( Feature & CF_USE2 )   TouchArg( cmd.Op2, 1 );
  if( Feature & CF_USE3 )   TouchArg( cmd.Op3, 1 );
  if( Feature & CF_JUMP )   QueueMark( Q_jumps, cmd.ea );

  if( Feature & CF_CHG1 )   TouchArg( cmd.Op1, 0 );
  if( Feature & CF_CHG2 )   TouchArg( cmd.Op2, 0 );
  if( Feature & CF_CHG3 )   TouchArg( cmd.Op3, 0 );

  switch ( cmd.itype )
  {
    case I196_popa:
      splitSRarea1(cmd.ea, WSR,  BADSEL, SR_auto);
      splitSRarea1(cmd.ea, WSR1, BADSEL, SR_auto);
      break;
  }

  if( flow )                ua_add_cref( 0, cmd.ea+cmd.size, fl_F );

  return 1;
}
