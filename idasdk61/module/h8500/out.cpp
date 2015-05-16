/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "h8500.hpp"
#include <srarea.hpp>

//----------------------------------------------------------------------
static void out_bad_address(ea_t addr)
{
  const char *name = find_sym((int)addr);
  if ( name != NULL )
  {
    out_line(name, COLOR_IMPNAME);
  }
  else
  {
    out_tagon(COLOR_ERROR);
    OutLong(addr, 16);
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
static int calc_sizer(op_t &x)
{
  if ( cmd.itype == H8500_mov_g && x.type == o_imm )
    return cmd.auxpref & aux_mov16 ? 16 : 8;
  // special case: cmp:g.b #x:8, @(d:16,r)
  // special case: cmp:g.w #x:16, @(d:8,r)
  else if ( cmd.itype == H8500_cmp_g && x.type == o_imm )
    return cmd.auxpref & aux_word ? 16 : 8;
  else
    return (cmd.auxpref & aux_disp24) ? 24 :
           (cmd.auxpref & aux_disp16) ? 16 : 8;
}

//----------------------------------------------------------------------
ea_t calc_mem(op_t &x)
{
  if ( x.type == o_near )
    return toEA(cmd.cs, x.addr);

// Before this was simply toEA, now we do it like this:
// (if someone complains, both methods should be retained)
  ea_t ea = x.addr;
  switch ( calc_sizer(x) )
  {
    case 8:
      if ( cmd.auxpref & aux_page )
      {
        ea &= 0xFF;
        sel_t br = getSR(cmd.ea, BR);
        if ( br != BADSEL )
          ea |= br << 8;
        else
          ea = BADADDR;
      }
      break;
    case 16:
      ea &= 0xFFFF;
      if ( x.type == o_mem )
      {
        sel_t dp = getSR(cmd.ea, DP);
        if ( dp != BADSEL )
          ea |= dp << 16;
        else
          ea = BADADDR;
      }
      else
      {
        ea |= cmd.ea & ~0xFFFF;
      }
      break;
  }
  return ea;
}

//----------------------------------------------------------------------
static void out_sizer(op_t &x)
{
  static char show_sizer = -1;
  if ( show_sizer == -1 ) show_sizer = getenv("H8_NOSIZER") == NULL;
  if ( !show_sizer ) return;
  if ( (cmd.auxpref & (aux_disp8|aux_disp16|aux_disp24)) == 0 ) return;
  out_symbol(':');
  // 1D 00 11 07 00 01                 mov:g.w #1:16, @0x11:16
  // 1D 00 11 06 01                    mov:g.w #1:16, @0x11:16
  // 0D 11 07 00 01                    mov:g.w #1:8, @0x11:8
  // 0D 11 06 01                       mov:g.w #1:8, @0x11:8
  // 0D 11 07 00 01                    mov:g.w #1:8, @0x11:8
  // 1D 00 11 07 00 01                 mov:g.w #1:16, @0x11:16
  // 15 00 11 06 01                    mov:g.b #1:16, @0x11:16
  // 05 11 06 01                       mov:g.b #1:8, @0x11:8
  int s = calc_sizer(x);
  out_long(s, 10);
}

//----------------------------------------------------------------------
static void out_reglist(int reg, int cnt)
{
  int bit = 1;
  int delayed = -1;
  int first = 1;
  for ( int i=0; i <= cnt; i++,bit<<=1 )
  {
    if ( (reg & bit) == 0 )
    {
      if ( delayed >= 0 )
      {
        if ( !first ) out_symbol(',');
        if ( delayed == (i-1) )
        {
          outreg(delayed);
        } else if ( delayed == (i-2) )
        {
          outreg(delayed);
          out_symbol(',');
          outreg(delayed+1);
        }
        else
        {
          outreg(delayed);
          out_symbol('-');
          outreg(i-1);
        }
        delayed = -1;
        first = 0;
      }
    }
    else
    {
      if ( delayed < 0 ) delayed = i;
    }
  }
}

//----------------------------------------------------------------------
int calc_opimm_flags(void)
{
  bool sign = cmd.itype == H8500_add_q
           || cmd.itype == H8500_adds
           || cmd.itype == H8500_subs;
  return OOFS_IFSIGN|OOFW_IMM|(sign ? OOF_SIGNED : 0);
}

//----------------------------------------------------------------------
int calc_opdispl_flags(void)
{
   bool sign = (cmd.auxpref & aux_disp8) != 0;
   return OOF_ADDR|OOFS_IFSIGN|(sign ? OOF_SIGNED : 0)|
                     ((cmd.auxpref & aux_disp24) ? OOFW_32 :
                      (cmd.auxpref & aux_disp16) ? OOFW_16 : OOFW_8);
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
      out_symbol('(');
      out_reglist(x.reg, 8);
      out_symbol(')');
      break;

    case o_imm:
      out_symbol('#');
      OutValue(x, calc_opimm_flags());
      out_sizer(x);
      break;

    case o_mem:
      out_symbol('@');
    case o_near:
    case o_far:
      {
        ea_t ea = calc_mem(x);
        if ( !out_name_expr(x, ea, BADADDR) )
          out_bad_address(x.addr);
        out_sizer(x);
      }
      break;

    case o_phrase:
      if ( x.phtype == ph_normal )
      {
        bool outdisp = isOff(uFlag,x.n)
                    || isStkvar(uFlag,x.n)
                    || isEnum(uFlag,x.n)
                    || isStroff(uFlag,x.n);
        if ( outdisp )
         goto OUTDISP;
      }
      out_symbol('@');
      if ( x.phtype == ph_pre  ) out_symbol('-');
      outreg(x.phrase);
      if ( x.phtype == ph_post ) out_symbol('+');
      break;

    case o_displ:
OUTDISP:
      out_symbol('@');
      out_symbol('(');
      OutValue(x, calc_opdispl_flags());
      out_sizer(x);
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
  else if ( cmd.auxpref & aux_word ) postfix = ".w";
  else if ( cmd.auxpref & aux_f    ) postfix = "/f";
  else if ( cmd.auxpref & aux_ne   ) postfix = "/ne";
  else if ( cmd.auxpref & aux_eq   ) postfix = "/eq";
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
    ".bss",     // bss (block started by storage) section, which loads zero-initialized data
  };

  segment_t *Sarea = getseg(ea);
  if ( is_spec_segm(Sarea->type) ) return;

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
                 strcmp(sclas,"CODE") == 0
                    ? ".text"
                    : strcmp(sclas,"BSS") == 0
                         ? ".bss"
                         : ".data",
                 ash.cmnt,
                 sname);
  if ( Sarea->orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), Sarea->orgbase);
    printf_line(inf.indent, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
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
void idaapi assume(ea_t ea)
{
  segreg_t *Darea  = getSRarea(ea);
  segment_t *Sarea = getseg(ea);
  char buf[MAXSTR];
  char *const end = buf + sizeof(buf);

  if ( Sarea == NULL || Darea == NULL || !inf.s_assume ) return;

  bool show = (ea == Sarea->startEA);
  if ( show || Darea->startEA == ea )
  {
    bool used = false;
    segreg_t our = *Darea;
    segreg_t *prev = show ? NULL : getSRarea(ea-1);
    char *ptr = NULL;
    for ( int i=ph.regFirstSreg; i <= ph.regLastSreg; i++ )
    {
      if ( i == ph.regCodeSreg ) continue;
      if ( prev == NULL || prev->reg(i) != our.reg(i) )
      {
        if ( !used )
        {
          ptr = tag_on(buf, end, COLOR_AUTOCMT);
          APPEND(ptr, end, ash.cmnt);
          APPEND(ptr, end, " assume ");
        }
        else
        {
          APPCHAR(ptr, end, ',');
          APPCHAR(ptr, end, ' ');
        }
        used = true;
        APPEND (ptr, end, ph.regNames[i]);
        APPCHAR(ptr, end, ':');
        if ( our.reg(i) == BADSEL )
          APPEND(ptr, end, "nothing");
        else
          ptr += btoa(ptr, end-ptr, our.reg(i), 16);
      }
    }
    if ( used )
    {
      tag_off(ptr, end, COLOR_AUTOCMT);
      MakeLine(buf, inf.indent);
    }
  }
}

//--------------------------------------------------------------------------
void idaapi header(void)
{
  gen_cmt_line("Processor       : %-8.8s", inf.procName);
  gen_cmt_line("Target assembler: %s", ash.name);
  gen_cmt_line("Byte sex        : %s", inf.mf ? "Big endian" : "Little endian");
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
