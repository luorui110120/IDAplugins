/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Output
 *
 */
#include "necv850.hpp"
#include <queue.hpp>
#include "ins.hpp"

//--------------------------------------------------------------------------
static void out_reg_list(uint32 L)
{
  // LIST12 table mapping to corresponding registers
  static const int list12_table[] =
  {
    rR31, // 0
    rR29, // 1
    rR28, // 2
    rR23, // 3
    rR22, // 4
    rR21, // 5
    rR20, // 6
    rR27, // 7
    rR26, // 8
    rR25, // 9
    rR24, // 10
    rEP   // 11
  };

  // Using the indexes in this table as indexes in list12_table[]
  // we can test for bits in List12 in order
  static const int list12order_table[] =
  {
    6,    // 0  r20
    5,    // 1  r21
    4,    // 2  r22
    3,    // 3  r23
    10,   // 4  r24
    9,    // 5  r25
    8,    // 6  r26
    7,    // 7  r27
    2,    // 8  r28
    1,    // 9  r29
    11,   // 10 r30
    0,    // 11 r31
  };

  int last = qnumber(list12_table);
  int in_order = 0, c = 0;
  const char *last_rn = NULL;

  out_symbol('{');
  for ( int i=0; i<qnumber(list12order_table); i++ )
  {
    uint32 idx = list12order_table[i];
    if ( (L & (1 << idx)) == 0 )
      continue;
    c++;
    const char *rn = RegNames[list12_table[idx]];
    if ( last + 1 == i )
      in_order++;
    else
    {
      if ( in_order > 1 )
      {
        out_symbol('-');
        out_register(last_rn);
        out_line(", ", COLOR_SYMBOL);
      }
      else if ( c > 1 )
      {
        out_line(", ", COLOR_SYMBOL);
      }
      out_register(rn);
      in_order = 1;
    }
    last_rn = rn;
    last    = i;
  }
  if ( in_order > 1 )
  {
    out_symbol('-');
    out_register(last_rn);
  }
  out_symbol('}');
}

//--------------------------------------------------------------------------
void idaapi nec850_header(void)
{
  gen_cmt_line("Processor:        %s", inf.procName);
  gen_cmt_line("Target assembler: %s", ash.name);
}

//--------------------------------------------------------------------------
void idaapi nec850_footer(void)
{
  char buf[MAXSTR];
  MakeNull();
  tag_addstr( buf, buf+sizeof(buf), COLOR_ASMDIR, ash.end );
  MakeLine(buf, inf.indent);
  gen_cmt_line( "-------------- end of module --------------");
}

//--------------------------------------------------------------------------
void idaapi nec850_segstart(ea_t ea)
{
  segment_t *s = getseg(ea);
  char sname[MAXNAMELEN], sclass[MAXNAMELEN];

  get_segm_name(s, sname, sizeof(sname));
  get_segm_class(s, sclass, sizeof(sclass));

  const char *p_class;
  if ( (s->perm == (SEGPERM_READ|SEGPERM_WRITE)) && s->type == SEG_BSS )
    p_class = "bss";
  else if ( s->perm == SEGPERM_READ )
    p_class = "const";
  else if ( s->perm == (SEGPERM_READ|SEGPERM_WRITE) )
    p_class = "data";
  else if ( s->perm == (SEGPERM_READ|SEGPERM_EXEC) )
    p_class = "text";
  else if ( s->type == SEG_XTRN )
    p_class = "symtab";
  else
    p_class = sclass;

  printf_line(0, COLSTR(".section \"%s\", %s", SCOLOR_ASMDIR), sname, p_class);
}

//--------------------------------------------------------------------------
void idaapi nec850_segend(ea_t /*ea*/)
{
}

//----------------------------------------------------------------------
inline void OutReg(op_t &r)
{
  bool brackets = r.specflag1 & N850F_USEBRACKETS;
  if ( brackets )
    out_symbol('[');
  out_register(ph.regNames[r.reg]);
  if ( brackets )
    out_symbol(']');
}

//----------------------------------------------------------------------
void idaapi nec850_out(void)
{
  char buf[MAXSTR];

  init_output_buffer(buf, sizeof(buf));
  OutMnem();

  out_one_operand( 0 );

  for ( int i=1; i<3; i++ )
  {
    if ( cmd.Operands[i].type != o_void )
    {
      out_symbol(',');
      OutChar(' ');
      out_one_operand(i);
    }
  }

  term_output_buffer();

  gl_comm = 1;
  MakeLine(buf);
}

//----------------------------------------------------------------------
// Generate text representation of an instructon operand.
// This function shouldn't change the database, flags or anything else.
// All these actions should be performed only by u_emu() function.
// The output text is placed in the output buffer initialized with init_output_buffer()
// This function uses out_...() functions from ua.hpp to generate the operand text
// Returns: 1-ok, 0-operand is hidden.
bool idaapi nec850_outop(op_t &x)
{
  switch( x.type )
  {
  case o_void:
    return false;
  case o_reglist:
    out_reg_list(x.value);
    break;
  case o_reg:
    OutReg(x);
    break;
  case o_imm:
    OutValue(x, OOFW_IMM | ((x.specflag1 & N850F_OUTSIGNED) ? OOF_SIGNED : 0));
    break;
  case o_near:
  case o_mem:
    if ( !out_name_expr(x, x.addr, BADADDR) )
    {
      out_tagon(COLOR_ERROR);
      OutValue(x, OOF_ADDR | OOFW_IMM | OOFW_32);
      out_tagoff(COLOR_ERROR);
      QueueMark(Q_noName,cmd.ea);
    }
    break;
  case o_displ:
    if ( x.addr != 0 || x.reg == rSP )
      OutValue(x,
          OOF_ADDR
        | OOFW_16
        | ((x.specflag1 & N850F_OUTSIGNED) ? OOF_SIGNED : 0));  // x.addr
    OutReg(x);
    break;
  default:
    return false;
  }
  return true;
}
