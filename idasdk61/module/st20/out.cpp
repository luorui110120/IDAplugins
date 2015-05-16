/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "st20.hpp"

//----------------------------------------------------------------------
inline void outreg(int r)
{
  out_register(ph.regNames[r]);
}

//----------------------------------------------------------------------
static void outmem(op_t &x, ea_t ea)
{
  if ( !out_name_expr(x, ea, BADADDR) )
  {
    out_tagon(COLOR_ERROR);
    OutLong(x.addr, 16);
    out_tagoff(COLOR_ERROR);
    QueueMark(Q_noName,cmd.ea);
  }
}

//----------------------------------------------------------------------
bool idaapi outop(op_t &x)
{
  switch ( x.type )
  {

    case o_void:
      return 0;

    case o_imm:
      OutValue(x, OOFS_IFSIGN|OOFW_IMM);
      break;

    case o_near:
      outmem(x, calc_mem(x.addr));
      break;

    default:
      interr("out");
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
void idaapi out(void)
{
  char buf[MAXSTR];
  init_output_buffer(buf, sizeof(buf));

  OutMnem();

  out_one_operand(0);
  if ( isVoid(cmd.ea, uFlag, 0) ) OutImmChar(cmd.Op1);

  term_output_buffer();
  gl_comm = 1;
  MakeLine(buf);
}

//--------------------------------------------------------------------------
void idaapi segstart(ea_t ea)
{
  segment_t *Sarea = getseg(ea);
  if ( is_spec_segm(Sarea->type) ) return;

  char sname[MAXNAMELEN];
  get_true_segm_name(Sarea, sname, sizeof(sname));

  gen_cmt_line("section %s", sname);
}

//--------------------------------------------------------------------------
void idaapi segend(ea_t)
{
}

//--------------------------------------------------------------------------
void idaapi header(void)
{
  gen_cmt_line("Processor       : %-8.8s", inf.procName);
//  gen_cmt_line("Target assembler: %s", ash.name);
//  gen_cmt_line("Byte sex        : %s", inf.mf ? "Big endian" : "Little endian");
//  if ( ash.header != NULL )
//    for ( const char **ptr=ash.header; *ptr != NULL; ptr++ )
//      printf_line(0,COLSTR("%s",SCOLOR_ASMDIR),*ptr);
  MakeNull();
}

//--------------------------------------------------------------------------
void idaapi footer(void)
{
  char name[MAXSTR];
  get_colored_name(BADADDR, inf.beginEA, name, sizeof(name));
  const char *end = ash.end;
  if ( end == NULL )
    printf_line(inf.indent,COLSTR("%s end %s",SCOLOR_AUTOCMT), ash.cmnt, name);
  else
    printf_line(inf.indent,COLSTR("%s",SCOLOR_ASMDIR)
                  " "
                  COLSTR("%s %s",SCOLOR_AUTOCMT), ash.end, ash.cmnt, name);
}

