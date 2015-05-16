/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2000 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "st7.hpp"

//----------------------------------------------------------------------
inline void outreg(int r)
{
  out_register(ph.regNames[r]);
}

//----------------------------------------------------------------------
static void outmem(op_t &x, ea_t ea)
{
  char buf[MAXSTR];
  if ( get_name_expr(cmd.ea+x.offb, x.n, ea, BADADDR, buf, sizeof(buf)) <= 0 )
  {
    const ioport_t *p = find_sym(x.addr);
    if ( p == NULL )
    {
      out_tagon(COLOR_ERROR);
      OutLong(x.addr, 16);
      out_tagoff(COLOR_ERROR);
      QueueMark(Q_noName,cmd.ea);
    }
    else
    {
      out_line(p->name, COLOR_IMPNAME);
    }
  }
  else
  {
    bool complex = strchr(buf, '+') || strchr(buf, '-');
    if ( complex ) out_symbol(ash.lbrace);
    OutLine(buf);
    if ( complex ) out_symbol(ash.rbrace);
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
      out_symbol('#');
      OutValue(x, OOFS_IFSIGN|OOFW_IMM);
      break;

    case o_displ:
// o_displ Short     Direct   Indexed  ld A,($10,X)             00..1FE                + 1
// o_displ Long      Direct   Indexed  ld A,($1000,X)           0000..FFFF             + 2
      out_symbol('(');
      OutValue(x, OOFS_IFSIGN
                 |OOF_ADDR
                 |((cmd.auxpref & aux_16) ? OOFW_16 : OOFW_8));
      out_symbol(',');
      outreg(x.reg);
      out_symbol(')');
      break;

    case o_phrase:
      out_symbol('(');
      outreg(x.reg);
      out_symbol(')');
      break;

    case o_mem:
// o_mem   Short     Direct            ld A,$10                 00..FF                 + 1
// o_mem   Long      Direct            ld A,$1000               0000..FFFF             + 2
// o_mem   Short     Indirect          ld A,[$10]               00..FF     00..FF byte + 2
// o_mem   Long      Indirect          ld A,[$10.w]             0000..FFFF 00..FF word + 2
// o_mem   Short     Indirect Indexed  ld A,([$10],X)           00..1FE    00..FF byte + 2
// o_mem   Long      Indirect Indexed  ld A,([$10.w],X)         0000..FFFF 00..FF word + 2
// o_mem   Relative  Indirect          jrne [$10]               PC+/-127   00..FF byte + 2
// o_mem   Bit       Direct            bset $10,#7              00..FF                 + 1
// o_mem   Bit       Indirect          bset [$10],#7            00..FF     00..FF byte + 2
// o_mem   Bit       Direct   Relative btjt $10,#7,skip         00..FF                 + 2
// o_mem   Bit       Indirect Relative btjt [$10],#7,skip       00..FF     00..FF byte + 3
      if ( cmd.auxpref & aux_index ) out_symbol('(');
      if ( cmd.auxpref & aux_indir ) out_symbol('[');
      outmem(x, calc_mem(x.addr));
      if ( cmd.auxpref & aux_long  ) out_symbol('.');
      if ( cmd.auxpref & aux_long  ) out_symbol('w');
      if ( cmd.auxpref & aux_indir ) out_symbol(']');
      if ( cmd.auxpref & aux_index )
      {
        out_symbol(',');
        outreg(x.reg);
        out_symbol(')');
      }
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
  char buf[MAXSTR];
  char *const end = buf + sizeof(buf);
  segment_t *Sarea = getseg(ea);
  if ( is_spec_segm(Sarea->type) ) return;

  const char *align;
  switch ( Sarea->align )
  {
    case saAbs:        align = "at: ";   break;
    case saRelByte:    align = "byte";  break;
    case saRelWord:    align = "word";  break;
    case saRelPara:    align = "para";  break;
    case saRelPage:    align = "page";  break;
    case saRel4K:      align = "4k";    break;
    case saRel64Bytes: align = "64";    break;
    default:           align = NULL;    break;
  }
  if ( align == NULL )
  {
    gen_cmt_line("Segment alignment '%s' can not be represented in assembly",
                 get_segment_alignment(Sarea->align));
    align = "";
  }

  char sname[MAXNAMELEN];
  char sclas[MAXNAMELEN];
  get_true_segm_name(Sarea, sname, sizeof(sname));
  get_segm_class(Sarea, sclas, sizeof(sclas));

  char *ptr = buf + qsnprintf(buf, sizeof(buf),
                              SCOLOR_ON SCOLOR_ASMDIR "%-*s segment %s ",
                              inf.indent-1,
                              sname,
                              align);
  if ( Sarea->align == saAbs )
  {
    ea_t absbase = get_segm_base(Sarea);
    ptr += btoa(ptr, end-ptr, absbase);
    APPCHAR(ptr, end, ' ');
  }
  const char *comb;
  switch ( Sarea->comb )
  {
    case scPub:
    case scPub2:
    case scPub3:    comb = "";        break;
    case scCommon:  comb = "common";  break;
    default:        comb = NULL;      break;
  }
  if ( comb == NULL )
  {
    gen_cmt_line("Segment combination '%s' can not be represented in assembly",
                 get_segment_combination(Sarea->comb));
    comb = "";
  }
  ptr += qsnprintf(ptr, end-ptr, "%s '%s'", comb, sclas);
  tag_off(ptr, end, COLOR_ASMDIR);
  MakeLine(buf, 0);
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

