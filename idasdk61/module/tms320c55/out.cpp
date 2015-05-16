/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "tms320c55.hpp"
#include <frame.hpp>
#include <srarea.hpp>
#include <struct.hpp>

//? problem with stack variables:
// SP+offsets point to a word, but stack variables works at the byte level
// => variables offsets aren't just

//----------------------------------------------------------------------
static void out_address(op_t &op)
{
  ea_t ea = BADADDR;
  if ( op.type == o_near )
    ea = calc_code_mem(op.addr);
  else if ( op.type == o_mem )
    ea = calc_data_mem(op);
  else if ( op.type == o_io )
   ea = calc_io_mem(op);

  int reg = -1;
  if ( op.type == o_mem) reg = get_mapped_register(ea );

  // print begin of the modifier
  switch ( op.tms_modifier )
  {
    case TMS_MODIFIER_NULL:
      break;
    case TMS_MODIFIER_DMA:
      if ( (int)reg == -1) out_symbol('@' );
      break;
    case TMS_MODIFIER_ABS16:
    case TMS_MODIFIER_PTR:
      out_symbol('*');
      if ( op.tms_modifier == TMS_MODIFIER_ABS16) out_line("abs16", COLOR_SYMBOL );
      out_line("(#", COLOR_SYMBOL);
      break;
    case TMS_MODIFIER_MMAP:
      out_line("mmap(@", COLOR_SYMBOL);
      break;
    case TMS_MODIFIER_PORT:
      out_line("port(#", COLOR_SYMBOL);
      break;
    case TMS_MODIFIER_PORT_AT:
      out_line("port(@", COLOR_SYMBOL);
      break;
    default:
      error("interr: out: o_address: modifier_begin");
  }


  if ( op.type != o_io )
  {
    if ( int(reg) != -1 ) // memory mapped register
      out_register(ph.regNames[reg]);
    else
    {
#ifndef TMS320C55_NO_NAME_NO_REF
      if ( !out_name_expr(op, ea, ea) )
#endif
      {
        out_tagon(COLOR_ERROR);
        if ( op.type != o_mem )
          OutLong(op.addr, 16);
        else
          OutLong(op.addr, 16);
        out_tagoff(COLOR_ERROR);
        QueueMark(Q_noName, cmd.ea);
      }
    }
  }
  else // IO address
  {
    if ( ea != BADADDR )
    {
      const char *name = NULL;
      if ( idpflags & TMS320C55_IO) name = find_sym(ea );
      if ( name )
        out_line(name, COLOR_IMPNAME);
      else
        OutLong(ea, 16);
    }
    else
    {
      out_tagon(COLOR_ERROR);
      OutLong(op.addr, 16);
      out_tagoff(COLOR_ERROR);
    }
  }

  // print end of the modifier
  switch ( op.tms_modifier )
  {
    case TMS_MODIFIER_NULL:
    case TMS_MODIFIER_DMA:
      break;
    case TMS_MODIFIER_ABS16:
    case TMS_MODIFIER_PTR:
    case TMS_MODIFIER_MMAP:
    case TMS_MODIFIER_PORT:
    case TMS_MODIFIER_PORT_AT:
      out_symbol(')'); break;
    default:
      error("interr: out: o_address: modifier_begin");
  }
}

static void out_shift(uval_t value)
{
  out_symbol('#');
  char buf[8];
  qsnprintf(buf, sizeof(buf), "%d", (int)value);
  out_line(buf,COLOR_DNUM);
}

// output shift symbol (if out = true, output outside of brackets)
static void out_symbol_shift(op_t &op, bool out = false)
{
  if ( op.tms_shift != TMS_OP_SHIFT_NULL )
  {
    if ( ((op.tms_shift & TMS_OP_SHIFT_OUT)!=0) == out ) // check if the shift must be print inside or outside the brackets
    {
      switch ( op.tms_shift & TMS_OP_SHIFT_TYPE )
      {
        case TMS_OP_SHIFTL_IMM:
          out_line(" << ",COLOR_SYMBOL);
          out_shift(op.tms_shift_value);
          break;
        case TMS_OP_SHIFTL_REG:
          out_line(" << ",COLOR_SYMBOL);
          out_register(ph.regNames[op.tms_shift_value]);
          break;
        case TMS_OP_SHIFTR_IMM:
          out_line(" >> ",COLOR_SYMBOL);
          out_shift(op.tms_shift_value);
          break;
        case TMS_OP_EQ:
          out_line(" == ",COLOR_SYMBOL);
          out_shift(op.tms_shift_value);
          break;
        case TMS_OP_NEQ:
          out_line(" != ",COLOR_SYMBOL);
          out_shift(op.tms_shift_value);
          break;
        default:
          error("interr: out: out_symbol_shift");
      }
    }
  }
}


static void out_operators_begin(op_t &op)
{
  static const char *const strings[TMS_OPERATORS_SIZE] =
  {
   "T3=",       "!",          "uns(",      "dbl(",
   "rnd(",      "pair(",      "lo(",       "hi(",
   "low_byte(", "high_byte(", "saturate(", "dual(",
   "port("
  };
  short operators = (op.tms_operator2 << 8) | (op.tms_operator1 &0xFF);
  for (int i = 0; i < TMS_OPERATORS_SIZE; i++)
    if ( operators & (1<<i)) out_line(strings[i], COLOR_SYMBOL );
}

static void out_operators_end(op_t &op)
{
  int i;
  short operators = (op.tms_operator2 << 8) | (op.tms_operator1 &0xFF);
  int brackets = 0;
  for (i = 0; i < TMS_OPERATORS_SIZE; i++)
    if ( operators & (1<<i) ) brackets++;
  if ( operators & TMS_OPERATOR_T3 ) brackets--;
  if ( operators & TMS_OPERATOR_NOT ) brackets--;
  for (i = 0; i < brackets; i++) out_register(")");
}


static void out_reg(op_t &op)
{
  const char *reg = ph.regNames[op.reg];

  switch ( op.tms_modifier )
  {
    case TMS_MODIFIER_NULL:
      out_register(reg);
      break;
    case TMS_MODIFIER_REG:
      out_symbol('*');
      out_register(reg);
      break;
    case TMS_MODIFIER_REG_P:
      out_symbol('*');
      out_register(reg);
      out_symbol('+');
      break;
    case TMS_MODIFIER_REG_M:
      out_symbol('*');
      out_register(reg);
      out_symbol('-');
      break;
    case TMS_MODIFIER_REG_P_T0:
      out_line("*(", COLOR_SYMBOL);
      out_register(reg);
      out_symbol('+');
      out_register(ph.regNames[T0]);
      out_symbol(')');
      break;
    case TMS_MODIFIER_REG_P_T1:
      out_line("*(", COLOR_SYMBOL);
      out_register(reg);
      out_symbol('+');
      out_register(ph.regNames[T1]);
      out_symbol(')');
      break;
    case TMS_MODIFIER_REG_M_T0:
      out_line("*(", COLOR_SYMBOL);
      out_register(reg);
      out_symbol('-');
      out_register(ph.regNames[T0]);
      out_symbol(')');
      break;
    case TMS_MODIFIER_REG_M_T1:
      out_line("*(", COLOR_SYMBOL);
      out_register(reg);
      out_symbol('-');
      out_register(ph.regNames[T1]);
      out_symbol(')');
      break;
    case TMS_MODIFIER_REG_T0:
      out_symbol('*');
      out_register(reg);
      out_symbol('(');
      out_register(ph.regNames[T0]);
      out_symbol(')');
      break;
    case TMS_MODIFIER_REG_OFFSET:
    case TMS_MODIFIER_P_REG_OFFSET:
      out_symbol('*');
      if ( op.tms_modifier == TMS_MODIFIER_P_REG_OFFSET) out_symbol('+' );
      out_register(reg);
      out_line("(#", COLOR_SYMBOL);
      OutValue(op, OOFS_IFSIGN|OOF_SIGNED|OOF_NUMBER|OOFW_IMM);
      out_symbol(')');
      break;
    case TMS_MODIFIER_REG_SHORT_OFFSET:
      out_symbol('*'); out_register(reg);
      out_line("(short(#", COLOR_SYMBOL);
      OutValue(op, OOFS_IFSIGN|OOF_SIGNED|OOF_NUMBER|OOFW_IMM);
      out_line("))", COLOR_SYMBOL);
      break;
    case TMS_MODIFIER_REG_T1:
      out_symbol('*');
      out_register(reg);
      out_symbol('(');
      out_register(ph.regNames[T1]);
      out_symbol(')');
      break;
    case TMS_MODIFIER_P_REG:
      out_symbol('+');
      out_register(reg);
      break;
    case TMS_MODIFIER_M_REG:
      out_symbol('-');
      out_register(reg);
      break;
    case TMS_MODIFIER_REG_P_T0B:
      out_line("*(", COLOR_SYMBOL);
      out_register(reg);
      out_symbol('+');
      out_register("T0B");
      out_symbol(')');
      break;
    case TMS_MODIFIER_REG_M_T0B:
      out_line("*(", COLOR_SYMBOL);
      out_register(reg);
      out_symbol('-');
      out_register("T0B");
      out_symbol(')');
      break;
    default:
      error("interr: out: o_reg: modifier");
  }
}


static void out_cond(op_t &x)
{
  const char *reg = ph.regNames[x.reg];
  switch ( x.value )
  {
    case 0x00:
      out_register(reg);
      out_line(" == #", COLOR_SYMBOL);
      out_long(0, 10);
      break;
    case 0x10:
      out_register(reg);
      out_line(" != #", COLOR_SYMBOL);
      out_long(0, 10);
      break;
    case 0x20:
      out_register(reg);
      out_line(" < #", COLOR_SYMBOL);
      out_long(0, 10);
      break;
    case 0x30:
      out_register(reg);
      out_line(" <= #", COLOR_SYMBOL);
      out_long(0, 10);
      break;
    case 0x40:
      out_register(reg);
      out_line(" > #", COLOR_SYMBOL);
      out_long(0, 10);
      break;
    case 0x50:
      out_register(reg);
      out_line(" >= #", COLOR_SYMBOL);
      out_long(0, 10);
      break;
    case 0x60:
      out_line("overflow(", COLOR_SYMBOL);
      out_register(reg);
      out_symbol(')');
      break;
    case 0x64:
      out_register(ph.regNames[TC1]);
      break;
    case 0x65:
      out_register(ph.regNames[TC2]);
      break;
    case 0x66:
      out_register(ph.regNames[CARRY]);
      break;
    case 0x68:
      out_register(ph.regNames[TC1]);
      out_line(" & ", COLOR_SYMBOL);
      out_register(ph.regNames[TC2]);
      break;
    case 0x69:
      out_register(ph.regNames[TC1]);
      out_line(" & !", COLOR_SYMBOL);
      out_register(ph.regNames[TC2]);
      break;
    case 0x6A:
      out_symbol('!');
      out_register(ph.regNames[TC1]);
      out_line(" & ", COLOR_SYMBOL);
      out_register(ph.regNames[TC2]);
      break;
    case 0x6B:
      out_symbol('!');
      out_register(ph.regNames[TC1]);
      out_line(" & !", COLOR_SYMBOL);
      out_register(ph.regNames[TC2]);
      break;
    case 0x70:
      out_line("!overflow(", COLOR_SYMBOL);
      out_register(reg);
      out_symbol(')');
      break;
    case 0x74:
      out_symbol('!');
      out_register(ph.regNames[TC1]);
      break;
    case 0x75:
      out_symbol('!');
      out_register(ph.regNames[TC2]);
      break;
    case 0x76:
      out_symbol('!');
      out_register(ph.regNames[CARRY]);
      break;
    case 0x78:
      out_register(ph.regNames[TC1]);
      out_line(" | ", COLOR_SYMBOL);
      out_register(ph.regNames[TC2]);
      break;
    case 0x79:
      out_register(ph.regNames[TC1]);
      out_line(" | !", COLOR_SYMBOL);
      out_register(ph.regNames[TC2]);
      break;
    case 0x7A:
      out_symbol('!');
      out_register(ph.regNames[TC1]);
      out_line(" | ", COLOR_SYMBOL);
      out_register(ph.regNames[TC2]);
      break;
    case 0x7B:
      out_symbol('!');
      out_register(ph.regNames[TC1]);
      out_line(" | !", COLOR_SYMBOL);
      out_register(ph.regNames[TC2]);
      break;
    case 0x7C:
      out_register(ph.regNames[TC1]);
      out_line(" ^ ", COLOR_SYMBOL);
      out_register(ph.regNames[TC2]);
      break;
    case 0x7D:
      out_register(ph.regNames[TC1]);
      out_line(" ^ !", COLOR_SYMBOL);
      out_register(ph.regNames[TC2]);
      break;
    case 0x7E:
      out_symbol('!');
      out_register(ph.regNames[TC1]);
      out_line(" ^ ", COLOR_SYMBOL);
      out_register(ph.regNames[TC2]);
      break;
    case 0x7F:
      out_symbol('!');
      out_register(ph.regNames[TC1]);
      out_line(" ^ !", COLOR_SYMBOL);
      out_register(ph.regNames[TC2]);
      break;
    default:
      error("interr: out: o_cond");
  }
}


static void out_relop(op_t &op)
{
  out_register(ph.regNames[op.reg]);

  const char *relop = NULL;
  switch ( op.tms_relop )
  {
    case 0:
      relop = " == ";
      break;
    case 1:
      relop = " < ";
      break;
    case 2:
      relop = " >= ";
      break;
    case 3:
      relop = " != ";
      break;
    default:
      error("interr: out: o_relop");
  }
  out_line(relop, COLOR_SYMBOL);

  switch ( op.tms_relop_type )
  {
    case TMS_RELOP_REG:
      out_register(ph.regNames[int(op.value)]);
      break;
    case TMS_RELOP_IMM:
      out_symbol('#');
      OutValue(op, OOFS_IFSIGN|OOF_SIGNED|OOF_NUMBER|OOFW_IMM);
      break;
  }
}

//----------------------------------------------------------------------
bool idaapi outop(op_t &op)
{
  switch ( op.type )
  {
    case o_void:
      return 0;

    case o_reg:
      out_operators_begin(op);
      out_reg(op);
      out_symbol_shift(op, false);
      out_operators_end(op);
      out_symbol_shift(op, true);
      break;

    case o_relop:
      out_relop(op);
      break;

    case o_shift:
      out_shift(op.value);
      break;

    case o_imm:
      if ( op.tms_prefix == 0 )
        out_symbol('#');
      else
        out_symbol(op.tms_prefix);
      if ( op.tms_signed )
        OutValue(op, OOFS_IFSIGN|OOF_SIGNED|OOFW_IMM);
      else
        OutValue(op, OOFW_IMM);
      out_symbol_shift(op);
      break;

    case o_near:
      out_address(op);
      break;

    case o_mem:
    case o_io:
      out_operators_begin(op);
      out_address(op);
      out_symbol_shift(op, false);
      out_operators_end(op);
      out_symbol_shift(op, true);
      break;

    case o_cond:
      out_cond(op);
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

  int op;

  if ( !(cmd.SpecialModes & TMS_MODE_USER_PARALLEL) )
  {
    if ( (cmd.SpecialModes & TMS_MODE_LR) || (cmd.SpecialModes & TMS_MODE_CR) )
    {
      out_line(cmd.get_canon_mnem(), COLOR_INSN);
      out_line((cmd.SpecialModes & TMS_MODE_LR) ? ".lr ":".cr ", COLOR_INSN);
    }
    else
      OutMnem();
  }
  else
  { // user-defined parallelism
    out_line("|| ", COLOR_INSN);
    out_line(cmd.get_canon_mnem(), COLOR_INSN);
    out_line(" ", COLOR_INSN);
  }

  for (op = 0; op < UA_MAXOP; op++)
  {
    if ( cmd.Operands[op].type == o_void ) break;
    if ( op != 0 ) // not the first operand
    {
      if ( cmd.Parallel != TMS_PARALLEL_BIT && op == cmd.Parallel ) // multi-line instruction
      {
        term_output_buffer();
        MakeLine(buf);
        // print the second instruction line
        init_output_buffer(buf, sizeof(buf));
        if ( cmd.SpecialModes & TMS_MODE_SIMULATE_USER_PARALLEL )
          out_line("|| ", COLOR_INSN);
        else
          out_line(":: ", COLOR_INSN);
        const char *insn2 = cmd.get_canon_mnem();
        insn2 += strlen(insn2);
        insn2++;
        out_line(insn2, COLOR_INSN);
      }
      else
        out_symbol(',');
      OutChar(' ');
    }
    // print the operand
    out_one_operand(op);
  }

  // print immediate values
  for (op = 0; op < UA_MAXOP; op++)
    if ( isVoid(cmd.ea, uFlag, op) ) OutImmChar(cmd.Operands[op]);

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
  switch ( reg )
  {
    case ARMS:
      if ( value == -1 ) break;
      printf_line(inf.indent,COLSTR(".arms_%s",SCOLOR_ASMDIR), value ? "on":"off");
      return;
    case CPL:
      if ( value == -1 ) break;
      printf_line(inf.indent,COLSTR(".cpl_%s",SCOLOR_ASMDIR), value ? "on":"off");
      return;
    case DP:
      if ( value == -1 ) break;
      printf_line(inf.indent,COLSTR(".dp %s",SCOLOR_ASMDIR), buf);
      return;
  }
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

  char sclas[MAXNAMELEN];
  get_segm_class(Sarea, sclas, sizeof(sclas));

  if ( strcmp(sclas,"CODE") == 0 )
    printf_line(inf.indent, COLSTR(".text", SCOLOR_ASMDIR));
  else if ( strcmp(sclas,"DATA") == 0 )
    printf_line(inf.indent, COLSTR(".data", SCOLOR_ASMDIR));
//    printf_line(inf.indent, COLSTR(".sect %s", SCOLOR_ASMDIR), sname);

  if ( Sarea->orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), Sarea->orgbase);
    printf_line(inf.indent, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
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
  gen_cmt_line("Byte sex        : %s, %s",
                  inf.mf ? "big-endian" : "little-endian",
                  inf.wide_high_byte_first ? "high_byte_first" : "high_byte_last");
  if ( ash.header != NULL )
    for ( const char **ptr=ash.header; *ptr != NULL; ptr++ )
      printf_line(0,COLSTR("%s",SCOLOR_ASMDIR),*ptr);
  MakeNull();
  printf_line(0,COLSTR("MY_BYTE .macro BYTE",SCOLOR_ASMDIR));
  printf_line(0,COLSTR("        .emsg \"ERROR - Impossible to generate 8bit bytes on this processor. Please convert them to 16bit words.\"",SCOLOR_ASMDIR));
  printf_line(0,COLSTR("        .endm",SCOLOR_ASMDIR));
  MakeNull();
}

//--------------------------------------------------------------------------
void idaapi footer(void)
{
  printf_line(inf.indent,COLSTR("%s",SCOLOR_ASMDIR),ash.end);
}

//--------------------------------------------------------------------------
void idaapi gen_stkvar_def(char *buf, size_t bufsize, const member_t *mptr, sval_t v)
{
  char sign = ' ';
  if ( v < 0 )
  {
    sign = '-';
    v = -v;
  }

  char name[MAXNAMELEN];
  name[0] = '\0';
  get_member_name(mptr->id, name, sizeof(name));

  char vstr[MAX_NUMBUF];
  btoa(vstr, sizeof(vstr), v);
  qsnprintf(buf, bufsize,
               COLSTR("  %s ",SCOLOR_KEYWORD)
               COLSTR("%c%s",SCOLOR_DNUM)
               COLSTR(",",SCOLOR_SYMBOL) " "
               COLSTR("%s",SCOLOR_LOCNAME),
               ash.a_equ,
               sign,
               vstr,
               name);
}
