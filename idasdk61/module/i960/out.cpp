/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "i960.hpp"

//----------------------------------------------------------------------
inline void outreg(int r)
{
  if ( r > MAXREG )
    warning("%a: outreg: illegal reg %d", cmd.ea, r);
  else
    out_register(ph.regNames[r]);
}

//----------------------------------------------------------------------
static void outmem(op_t &x, ea_t ea)
{
  if ( !out_name_expr(x, ea, BADADDR) )
  {
    const char *p = find_sym(x.addr);
    if ( p == NULL )
    {
      out_tagon(COLOR_ERROR);
      OutLong(x.addr, 16);
      out_tagoff(COLOR_ERROR);
      QueueMark(Q_noName,cmd.ea);
    }
    else
    {
      out_line(p, COLOR_IMPNAME);
    }
  }
}

//----------------------------------------------------------------------
bool idaapi outop(op_t &x)
{
  switch ( x.type )
  {

    case o_void:
      return 0;

    case o_reg:
      outreg(x.reg);
      break;

    case o_imm:
      OutValue(x, OOFS_IFSIGN|OOFW_IMM);
      break;

    case o_displ:
      if ( x.addr != 0
        || isOff(uFlag,x.n)
        || isStkvar(uFlag,x.n)
        || isEnum(uFlag,x.n)
        || isStroff(uFlag,x.n) )
      {
        OutValue(x, OOFS_IFSIGN|OOF_SIGNED|OOF_ADDR|OOFW_32);
      }
      // no break
    case o_phrase:
      if ( uchar(x.reg) != uchar(-1) )
      {
        out_symbol('(');
        outreg(x.reg);
        out_symbol(')');
      }
      if ( uchar(x.index) != uchar(-1) )
      {
        out_symbol('[');
        outreg(x.index);
        if ( x.scale != 1 )
        {
          out_tagon(COLOR_SYMBOL);
          OutChar('*');
          OutLong(x.scale, 10);
          out_tagoff(COLOR_SYMBOL);
        }
        out_symbol(']');
      }
      break;

    case o_mem:
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

  const char *postfix = NULL;
//  if ( cmd.auxpref & aux_t ) postfix = ".t";
  if ( cmd.auxpref & aux_f ) postfix = ".f";
  OutMnem(8, postfix);

  out_one_operand(0);
  if ( cmd.Op2.type != o_void )
  {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(1);
  }
  if ( cmd.Op3.type != o_void )
  {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(2);
  }

  if ( isVoid(cmd.ea, uFlag, 0) ) OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea, uFlag, 1) ) OutImmChar(cmd.Op2);

  term_output_buffer();
  gl_comm = 1;
  MakeLine(buf);
}

//--------------------------------------------------------------------------
void idaapi segstart(ea_t ea)
{
  const char *const predefined[] =
  {
    ".text",    // Text section
//    ".rdata",   // Read-only data section
    ".data",    // Data sections
//    ".lit8",    // Data sections
//    ".lit4",    // Data sections
//    ".sdata",   // Small data section, addressed through register $gp
//    ".sbss",    // Small bss section, addressed through register $gp
//    ".bss",     // bss (block started by storage) section, which loads zero-initialized data
  };

  segment_t *Sarea = getseg(ea);
  if ( is_spec_segm(Sarea->type) ) return;

  char sname[MAXNAMELEN];
  char sclas[MAXNAMELEN];
  get_true_segm_name(Sarea, sname, sizeof(sname));
  get_segm_class(Sarea, sclas, sizeof(sclas));

  if ( strcmp(sname, ".bss") == 0 )
  {
    int align = 0;
    switch ( Sarea->align )
    {
      case saAbs:        align = 0;  break;
      case saRelByte:    align = 0;  break;
      case saRelWord:    align = 1;  break;
      case saRelPara:    align = 4;  break;
      case saRelPage:    align = 8;  break;
      case saRelDble:    align = 2;  break;
      case saRel4K:      align = 12; break;
      case saGroup:      align = 0;  break;
      case saRel32Bytes: align = 5;  break;
      case saRel64Bytes: align = 6;  break;
      case saRelQword:   align = 3;  break;
    };
    asize_t size = Sarea->type == SEG_NULL ? 0 : Sarea->size();
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), size);
    printf_line(inf.indent, COLSTR("%s %s, %d", SCOLOR_ASMDIR),
                                        sname, buf, align);
  }
  else
  {
    int i;
    for ( i=0; i < qnumber(predefined); i++ )
      if ( strcmp(sname, predefined[i]) == 0 )
        break;
    if ( i != qnumber(predefined) )
      printf_line(inf.indent, COLSTR("%s", SCOLOR_ASMDIR), sname);
    else
      printf_line(inf.indent, COLSTR("%s", SCOLOR_ASMDIR) ""
                      COLSTR("%s %s", SCOLOR_AUTOCMT),
                   strcmp(sclas,"CODE") == 0
                      ? ".text"
                      : ".data",
                   ash.cmnt,
                   sname);
  }
}

//--------------------------------------------------------------------------
void idaapi segend(ea_t)
{
}

//--------------------------------------------------------------------------
void idaapi header(void)
{
  gen_cmt_line("Processor       : %-8.8s", inf.procName);
  gen_cmt_line("Target assembler: %s", ash.name);
//  gen_cmt_line("Byte sex        : %s", inf.mf ? "Big endian" : "Little endian");
  if ( ash.header != NULL )
    for ( const char **ptr=ash.header; *ptr != NULL; ptr++ )
      printf_line(0,COLSTR("%s",SCOLOR_ASMDIR),*ptr);
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

