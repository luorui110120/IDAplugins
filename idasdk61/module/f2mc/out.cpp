/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "f2mc.hpp"
#include <frame.hpp>
#include <srarea.hpp>
#include <struct.hpp>

//----------------------------------------------------------------------
static void out_address(ea_t ea,op_t &x)
{
  if ( !out_name_expr(x, ea, x.addr) )
  {
    out_tagon(COLOR_ERROR);
    OutLong(x.addr, 16);
    out_tagoff(COLOR_ERROR);
    QueueMark(Q_noName, cmd.ea);
  }
}

//----------------------------------------------------------------------
static void out_reglist(ushort reglist)
{
  out_symbol('(');
  bool first = true;
  int i = 0;
  while ( i < 8 )
  {
    int size = 1;
    if ( (reglist>>i) & 1 )
    {
      while ( (i + size < 8) && ((reglist>>(i+size)) & 1 ) ) size++;
      if ( first ) first = false;
        else out_symbol(',');
      out_register(ph.regNames[RW0+i]);
      if ( size > 1 )
      {
        out_symbol('-');
        out_register(ph.regNames[RW0+i+size-1]);
      }
    }
    i+=size;
  }
  out_symbol(')');
}

//----------------------------------------------------------------------
bool exist_bits(ea_t ea, int bitl, int bith)
{
  for (int i = bitl; i <= bith; i++)
    if ( find_bit(ea, i) ) return true;
  return false;
}

// adjust to respect 16 bits an 32 bits definitions
static void adjust_ea_bit(ea_t &ea, int &bit)
{
  if ( find_sym(ea) ) return;
  if ( find_sym(ea-1) && exist_bits(ea-1, 8, 15) )
  {
    ea--;
    bit+=8;
    return;
  }
  if ( find_sym(ea-2) && exist_bits(ea-2, 16, 31) )
  {
    ea-=2;
    bit+=16;
    return;
  }
  if ( find_sym(ea-3) && exist_bits(ea-3, 16, 31) )
  {
    ea-=3;
    bit+=24;
    return;
  }
}

//----------------------------------------------------------------------
bool idaapi outop(op_t &x)
{
  ea_t ea;

  if ( cmd.prefix_bank && (cmd.op_bank == x.n )
    && (cmd.prefix_bank != cmd.default_bank))
  {
    out_register(ph.regNames[cmd.prefix_bank]);
    out_symbol(':');
  }

  for (int i = 0; i < x.at; i++) out_symbol('@');

  switch ( x.type )
  {
    case o_void:
      return 0;

    case o_reg:
      out_register(ph.regNames[x.reg]);
      break;

    case o_near:
      out_address(calc_code_mem(x.addr), x);
      break;

    case o_imm:
      out_symbol('#');
      OutValue(x, OOFS_IFSIGN|OOFW_IMM);
      break;

    case o_mem:
      {
        ea = calc_data_mem(x.addr);
        if ( x.addr_dtyp != 'i' ) // data address
        {
          if ( x.addr_dtyp )
          {
            out_symbol(x.addr_dtyp);
            out_symbol(':');
          }
          out_address(ea, x);
          if ( x.special_mode == MODE_BIT )
          {
            out_symbol(':');
            out_symbol('0' + x.byte_bit);
          }
        }
        else // IO address
        {
          int bit = x.byte_bit;
          out_symbol('i'); out_symbol(':');
          if ( x.special_mode == MODE_BIT) adjust_ea_bit(ea, bit );
          const char *name = find_sym(ea);
          if ( name )
          {
            out_addr_tag(ea);
            out_line(name, COLOR_IMPNAME);
          }
          else out_address(ea, x);
          if ( x.special_mode == MODE_BIT )
          {
            name = find_bit(ea,bit);
            if ( name )
            {
              out_symbol('_');
              out_line(name, COLOR_IMPNAME);
            }
            else
            {
              out_symbol(':');
              out_tagon(COLOR_SYMBOL);
              OutLong(bit, 10);
              out_tagoff(COLOR_SYMBOL);
            }
          }
        }
      }
      break;

    case o_phrase:
      out_register(ph.regNames[x.reg]);
      switch ( x.special_mode )
      {
        case MODE_INC:
          out_symbol('+');
          break;
        case MODE_INDEX:
          out_symbol('+');
          out_register(ph.regNames[x.index]);
          break;
      }
      break;

    case o_displ:
      out_register(ph.regNames[x.reg]);
      switch ( x.addr_dtyp )
      {
        case dt_byte:
          OutValue(x, OOF_ADDR|OOFS_NEEDSIGN|OOF_SIGNED|OOFW_8);
          break;
        case dt_word:
          OutValue(x, OOF_ADDR|OOFS_NEEDSIGN|OOF_SIGNED|OOFW_16);
          break;
      }
      break;

    case o_reglist:
      out_reglist(x.reg);
      break;

    default:
      error("interr: out");
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
    if ( cmd.Op3.type != o_void )
    {
      out_symbol(',');
      OutChar(' ');
      out_one_operand(2);
    }
  }
  if ( isVoid(cmd.ea, uFlag, 0) ) OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea, uFlag, 1) ) OutImmChar(cmd.Op2);
  if ( isVoid(cmd.ea, uFlag, 2) ) OutImmChar(cmd.Op3);

  term_output_buffer();
  gl_comm = 1;
  MakeLine(buf);
}

//--------------------------------------------------------------------------
static void print_segment_register(int reg, sel_t value)
{
  if ( reg == ph.regDataSreg ) return;
  char buf[MAX_NUMBUF];
  btoa(buf, sizeof(buf), value);
  gen_cmt_line("assume %s = %s", ph.regNames[reg], buf);
}

//--------------------------------------------------------------------------
// function to produce assume directives
void idaapi assumes(ea_t ea)
{
  segreg_t *Darea  = getSRarea(ea);
  segment_t *Sarea = getseg(ea);
  if ( Sarea == NULL || Darea == NULL || !inf.s_assume ) return;

  for ( int i=ph.regFirstSreg; i <= ph.regLastSreg; i++ )
  {
    if ( i == ph.regCodeSreg ) continue;
    sel_t now  = getSR(ea, i);
    bool show = (ea == Sarea->startEA);
    if ( show || Darea->startEA == ea )
    {
      segreg_t *prev = getSRarea(ea-1);
      if ( show || (prev != NULL && getSR(prev->startEA, i) != now) )
        print_segment_register(i, now);
    }
  }
}

//--------------------------------------------------------------------------
void idaapi segstart(ea_t ea)
{
  segment_t *Sarea = getseg(ea);
  if ( is_spec_segm(Sarea->type) ) return;

  char sname[MAXNAMELEN];
  char sclas[MAXNAMELEN];
  get_true_segm_name(Sarea, sname, sizeof(sname));
  get_segm_class(Sarea, sclas, sizeof(sclas));

  printf_line(inf.indent, COLSTR(".section %s, %s", SCOLOR_ASMDIR),
    sname,
    strcmp(sclas,"CODE") == 0 ? "code"
    : strcmp(sclas,"BSS") == 0 ? "data"
    : "const");
  if ( Sarea->orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), Sarea->orgbase);
    printf_line(inf.indent, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
void idaapi segend(ea_t) {
}

//--------------------------------------------------------------------------
void idaapi header(void)
{
  char buf[MAXSTR];
  gen_cmt_line("Processor       : %s [%s]", device[0] ? device : inf.get_proc_name(buf), deviceparams);
  gen_cmt_line("Target assembler: %s", ash.name);
  printf_line(0,"");
  printf_line(0,COLSTR("#include <_ffmc16_a.asm>",SCOLOR_ASMDIR));
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
  printf_line(inf.indent,
              COLSTR("%s",SCOLOR_ASMDIR) " " COLSTR("%s %s",SCOLOR_AUTOCMT),
              ash.end,
              ash.cmnt,
              name);
}
