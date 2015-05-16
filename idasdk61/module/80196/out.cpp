/*
 *  Interactive disassembler (IDA).
 *  Intel 80196 module
 *
 */

#include "i196.hpp"

//--------------------------------------------------------------------------

void idaapi header( void )
{
  gen_cmt_line( "Processor:        %s", inf.procName );
  gen_cmt_line( "Target assembler: %s", ash.name );
}

//--------------------------------------------------------------------------

void idaapi footer( void )
{
  gen_cmt_line( "end of file" );
}

//--------------------------------------------------------------------------

void idaapi segstart( ea_t ea )
{
  segment_t *Sarea = getseg( ea );

  char name[MAXNAMELEN];
  get_segm_name(Sarea, name, sizeof(name));
  gen_cmt_line( COLSTR("segment %s", SCOLOR_AUTOCMT), name );

  ea_t org = ea - get_segm_base( Sarea );
  if ( org != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), org);
    gen_cmt_line("%s %s", ash.origin, buf);
  }
}

//--------------------------------------------------------------------------

void idaapi segend( ea_t ea )
{
  char name[MAXNAMELEN];
  get_segm_name(getseg(ea-1), name, sizeof(name));
  gen_cmt_line( "end of '%s'", name );
}

//----------------------------------------------------------------------

void idaapi out( void )
{
  char buf[MAXSTR];

  init_output_buffer(buf, sizeof(buf));
  OutMnem();

  out_one_operand( 0 );

  if( cmd.Op2.type != o_void )
  {
    out_symbol( ',' );
    OutChar( ' ' );
    out_one_operand( 1 );
  }

  if( cmd.Op3.type != o_void )
  {
    out_symbol( ',' );
    OutChar( ' ' );
    out_one_operand( 2 );
  }

  if( isVoid( cmd.ea, uFlag, 0 ) )    OutImmChar( cmd.Op1 );
  if( isVoid( cmd.ea, uFlag, 1 ) )    OutImmChar( cmd.Op2 );
  if( isVoid( cmd.ea, uFlag, 2 ) )    OutImmChar( cmd.Op3 );

  term_output_buffer();
  gl_comm = 1;
  MakeLine( buf );
}

//----------------------------------------------------------------------
static bool is_ext_insn(void)
{
  switch ( cmd.itype )
  {
    case I196_ebmovi:      // Extended interruptable block move
    case I196_ebr:         // Extended branch indirect
    case I196_ecall:       // Extended call
    case I196_ejmp:        // Extended jump
    case I196_eld:         // Extended load word
    case I196_eldb:        // Extended load byte
    case I196_est:         // Extended store word
    case I196_estb:        // Extended store byte
      return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool idaapi outop( op_t &x )
{
  uval_t v, v1;
//  const char *ptr;

  switch( x.type )
  {
    case o_imm:
      out_symbol( '#' );
      OutValue( x, OOF_SIGNED | OOFW_IMM );
      break;

    case o_indexed:
      OutValue( x, OOF_ADDR|OOF_SIGNED|(is_ext_insn() ? OOFW_32 : OOFW_16) ); //.addr
      v = x.value;
      out_symbol( '[' );
      if ( v != 0 ) goto OUTPHRASE;
      out_symbol( ']' );
      break;

    case o_indirect:
    case o_indirect_inc:
      out_symbol( '[' );

    case o_mem:
    case o_near:
      v = x.addr;
OUTPHRASE:
      v1 = toEA( getSR(cmd.ea, (x.type == o_near) ? rVcs : rVds), v);
      if( !out_name_expr( x, v1, v ) )
      {
        OutValue( x, (x.type == o_indexed ? 0 : OOF_ADDR) | OOF_NUMBER|OOFS_NOSIGN|
          ((x.type == o_near) ? (is_ext_insn() ? OOFW_32 : OOFW_16) : OOFW_8) );
        QueueMark( Q_noName, cmd.ea );
      }

      if( x.type == o_indirect || x.type == o_indirect_inc ||
          x.type == o_indexed )
      {
        out_symbol( ']' );
        if( x.type == o_indirect_inc )    out_symbol( '+' );
      }
      break;

    case o_void:
      return 0;

    case o_bit:
      out_symbol( char('0' + x.reg) );
      break;

    default:
      warning( "out: %a: bad optype %d", cmd.ea, x.type );
  }

  return 1;
}
