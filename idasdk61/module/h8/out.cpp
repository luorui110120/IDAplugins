/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "h8.hpp"

//----------------------------------------------------------------------
static int get_size_value(void)
{
  return (cmd.auxpref & aux_disp32) ? 32 :
         (cmd.auxpref & aux_disp24) ? 24 :
         (cmd.auxpref & aux_disp16) ? 16 : 8;
}

//----------------------------------------------------------------------
int get_displ_outf(const op_t &x)
{
  return OOF_ADDR|OOFS_IFSIGN|OOF_SIGNED|
        ((isStkvar(uFlag,x.n) || (cmd.auxpref & aux_disp32)) ? OOFW_32 : OOFW_16);
}

//----------------------------------------------------------------------
static void out_bad_address(ea_t addr)
{
  const char *name = find_sym(advanced() ? addr : ushort(addr));
  if ( name != NULL )
  {
    out_line(name, COLOR_IMPNAME);
  }
  else
  {
    out_tagon(COLOR_ERROR);
    int sv = get_size_value();
    uint32 mask = uint32(-1) >> (32-sv);
    OutLong(addr & mask, 16);
    out_tagoff(COLOR_ERROR);
    QueueMark(Q_noName, cmd.ea);
  }
}

//----------------------------------------------------------------------
inline void outreg(int r)
{
  out_register(ph.regNames[r]);
}

//----------------------------------------------------------------------
ea_t calc_mem(ea_t ea)
{
  return toEA(cmd.cs, ea);
}

//----------------------------------------------------------------------
static void out_sizer(void)
{
  static char show_sizer = -1;
  if ( show_sizer == -1 ) show_sizer = getenv("H8_NOSIZER") == NULL;
  if ( !show_sizer ) return;
  out_symbol(':');
  out_long(get_size_value(), 10);
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

    case o_reglist:
      outreg(x.reg);
      out_symbol('-');
      outreg(x.reg+x.nregs-1);
      break;

    case o_imm:
      out_symbol('#');
      OutValue(x, OOFS_IFSIGN|OOFW_IMM);
      break;

    case o_memind:
      out_symbol('@');
    case o_mem:
      out_symbol('@');
    case o_near:
      {
        ea_t ea = calc_mem(x.addr);
        if ( !out_name_expr(x, ea, x.addr) )
          out_bad_address(x.addr);
        out_sizer();
      }
      break;

    case o_phrase:
      out_symbol('@');
      if ( x.phtype == ph_pre  ) out_symbol('-');
      outreg(x.phrase);
      if ( x.phtype == ph_post ) out_symbol('+');
      break;

    case o_displ:
      out_symbol('@');
      out_symbol('(');
      OutValue(x, get_displ_outf(x));
      out_sizer();
      out_symbol(',');
      outreg(x.reg);
      out_symbol(')');
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
  if ( cmd.auxpref & aux_byte ) postfix = ".b";
  if ( cmd.auxpref & aux_word ) postfix = ".w";
  if ( cmd.auxpref & aux_long ) postfix = ".l";
  OutMnem(8, postfix);

  out_one_operand(0);
  if ( cmd.Op2.type != o_void )
  {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(1);
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
  const char *predefined[] =
  {
    ".text",    // Text section
    ".rdata",   // Read-only data section
    ".data",    // Data sections
    ".lit8",    // Data sections
    ".lit4",    // Data sections
    ".sdata",   // Small data section, addressed through register $gp
    ".sbss",    // Small bss section, addressed through register $gp
  };

  segment_t *Sarea = getseg(ea);
  if ( Sarea == NULL || is_spec_segm(Sarea->type) ) return;

  char sname[MAXNAMELEN];
  char sclas[MAXNAMELEN];
  get_true_segm_name(Sarea, sname, sizeof(sname));
  get_segm_class(Sarea, sclas, sizeof(sclas));

  int i;
  for ( i=0; i < qnumber(predefined); i++ )
    if ( strcmp(sname, predefined[i]) == 0 )
      break;
  if ( i != qnumber(predefined) )
    printf_line(inf.indent, COLSTR("%s", SCOLOR_ASMDIR), sname);
  else
    printf_line(inf.indent, COLSTR("%s", SCOLOR_ASMDIR) "" COLSTR("%s %s", SCOLOR_AUTOCMT),
                 strcmp(sclas,"CODE") == 0 ? ".text" : ".data",
                 ash.cmnt,
                 sname);
}

//--------------------------------------------------------------------------
void idaapi segend(ea_t) {
#if 0
  segment_t *s = getseg(ea-1);
  if ( is_spec_segm(s->type) ) return;
  printf_line(0,COLSTR(";%-*s ends",SCOLOR_AUTOCMT),inf.indent-2,get_segm_name(s));
#endif
}

//--------------------------------------------------------------------------
void idaapi header(void) {
  gen_cmt_line("Processor       : %-8.8s", inf.procName);
  gen_cmt_line("Target assembler: %s", ash.name);
  gen_cmt_line("Byte sex        : %s", inf.mf ? "Big endian" : "Little endian");
  if ( ash.header != NULL )
    for ( const char **ptr=ash.header; *ptr != NULL; ptr++ )
      printf_line(0,COLSTR("%s",SCOLOR_ASMDIR),*ptr);
  const char *procdir = NULL;
       if ( ptype & P2000 ) procdir = COLSTR(".h8300s",SCOLOR_ASMDIR);
  else if ( ptype & ADV   ) procdir = COLSTR(".h8300h",SCOLOR_ASMDIR);
  if ( procdir != NULL )
  {
    MakeNull();
    printf_line(inf.indent, "%s", procdir);
  }
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
    printf_line(inf.indent,
                COLSTR("%s",SCOLOR_ASMDIR) " " COLSTR("%s %s",SCOLOR_AUTOCMT),
                ash.end,
                ash.cmnt,
                name);
}
