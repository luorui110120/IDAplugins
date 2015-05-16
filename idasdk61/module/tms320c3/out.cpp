/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "tms320c3x.hpp"
#include <frame.hpp>
#include <srarea.hpp>
#include <struct.hpp>

static const char * const formats[] =
{
        COLSTR("*+%s(", SCOLOR_REG) COLSTR("%02Xh", SCOLOR_NUMBER) COLSTR(")",  SCOLOR_REG),
        COLSTR("*-%s(", SCOLOR_REG) COLSTR("%02Xh", SCOLOR_NUMBER) COLSTR(")",  SCOLOR_REG),
        COLSTR("*++%s(",SCOLOR_REG) COLSTR("%02Xh", SCOLOR_NUMBER) COLSTR(")",  SCOLOR_REG),
        COLSTR("*--%s(",SCOLOR_REG) COLSTR("%02Xh", SCOLOR_NUMBER) COLSTR(")",  SCOLOR_REG),
        COLSTR("*%s++(",SCOLOR_REG) COLSTR("%02Xh", SCOLOR_NUMBER) COLSTR(")",  SCOLOR_REG),
        COLSTR("*%s--(",SCOLOR_REG) COLSTR("%02Xh", SCOLOR_NUMBER) COLSTR(")",  SCOLOR_REG),
        COLSTR("*%s++(",SCOLOR_REG) COLSTR("%02Xh", SCOLOR_NUMBER) COLSTR(")%%",SCOLOR_REG),
        COLSTR("*%s--(",SCOLOR_REG) COLSTR("%02Xh", SCOLOR_NUMBER) COLSTR(")%%",SCOLOR_REG),
        COLSTR("*+%s(ir0)",     SCOLOR_REG),
        COLSTR("*-%s(ir0)",     SCOLOR_REG),
        COLSTR("*++%s(ir0)",    SCOLOR_REG),
        COLSTR("*--%s(ir0)",    SCOLOR_REG),
        COLSTR("*%s++(ir0)",    SCOLOR_REG),
        COLSTR("*%s--(ir0)",    SCOLOR_REG),
        COLSTR("*%s++(ir0)%%",  SCOLOR_REG),
        COLSTR("*%s--(ir0)%%",  SCOLOR_REG),
        COLSTR("*+%s(ir1)",     SCOLOR_REG),
        COLSTR("*-%s(ir1)",     SCOLOR_REG),
        COLSTR("*++%s(ir1)",    SCOLOR_REG),
        COLSTR("*--%s(ir1)",    SCOLOR_REG),
        COLSTR("*%s++(ir1)",    SCOLOR_REG),
        COLSTR("*%s--(ir1)",    SCOLOR_REG),
        COLSTR("*%s++(ir1)%%",  SCOLOR_REG),
        COLSTR("*%s--(ir1)%%",  SCOLOR_REG),
        COLSTR("*%s",           SCOLOR_REG),
        COLSTR("*%s++(ir0)B",   SCOLOR_REG)
};

//--------------------------------------------------------------------------
static const char * const cc_text[] =
{
        //Unconditional compares
        "u",    //Unconditional

        //Unsigned compares
        "lo",   //Lower than
        "ls",   //Lower than or same as
        "hi",   //Higher than
        "hs",   //Higher than or same as
        "e",    //Equal to
        "ne",   //Not equal to

        //Signed compares
        "lt",   //Less than
        "le",   //Less than or equal to
        "gt",   //Greater than
        "ge",   //Greater than or equal to

        //Unknown
        "?",    //Unknown

        //Compare to condition flags
        "nv",   //No overflow
        "v",    //Overflow
        "nuf",  //No underflow
        "uf",   //Underflow
        "nlv",  //No latched overflow
        "lv",   //Latched overflow
        "nluf", //No latched floating-point underflow
        "luf",  //Latched floating-point underflow
        "zuf"   //Zero or floating-point underflow
};

//----------------------------------------------------------------------
static void out_address(ea_t ea, op_t &x, bool at)
{
    char buf[MAXSTR];
    if ( get_name_expr(cmd.ea+x.offb, x.n, ea, ea, buf, sizeof(buf)) > 0 )
    {
      if ( at) out_symbol('@' );
      OutLine(buf);
    }
    else
    {
      if ( at) out_symbol('@' );
          out_tagon(COLOR_ERROR);
          OutValue(x, OOFW_IMM|OOF_ADDR|OOFW_16);
          out_snprintf(" (ea = %a)", ea);
          out_tagoff(COLOR_ERROR);
          QueueMark(Q_noName, cmd.ea);
    }

}

//----------------------------------------------------------------------
bool idaapi outop(op_t &x)
{
  ea_t ea;
  char buf[MAXSTR];

  switch ( x.type )
  {
    case o_void:
      return 0;

    case o_reg:
      out_register(ph.regNames[x.reg]);
      break;

    case o_near:
      out_address( calc_code_mem(x), x, false);
      break;

    case o_imm:
      if ( cmd.itype != TMS320C3X_TRAPcond)     out_symbol('#' );

          if ( cmd.auxpref & ImmFltFlag )
          {
      int16 v = int16(x.value);
                  out_real(&v, 2, buf, sizeof(buf));
                  out_line(buf[0] == ' ' ? &buf[1] : buf, COLOR_NUMBER);
          }
          else
                  OutValue(x, OOFW_IMM);

      break;

    case o_mem:
      ea = calc_data_mem(x);
      if ( ea != BADADDR )
        out_address(ea, x, true);
      else
      {
        out_tagon(COLOR_ERROR);
        OutValue(x, OOFW_IMM|OOF_ADDR|OOFW_16);
        out_tagoff(COLOR_ERROR);
      }
      break;

    case o_phrase: // Indirect addressing mode
      {
        const char *reg = ph.regNames[uchar(x.phtype)];
        out_snprintf(formats[uchar(x.phrase)], reg, x.addr);
        break;
      }

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

  // output instruction mnemonics
  char postfix[8];
  postfix[0] = '\0';
  switch ( cmd.itype )
  {
    case TMS320C3X_LDFcond:
    case TMS320C3X_LDIcond:
    case TMS320C3X_Bcond:
    case TMS320C3X_DBcond:
    case TMS320C3X_CALLcond:
    case TMS320C3X_TRAPcond:
    case TMS320C3X_RETIcond:
    case TMS320C3X_RETScond:
                qstrncpy(postfix, cc_text[cmd.auxpref & 0x1f ], sizeof(postfix));
                if ( cmd.auxpref & DBrFlag ) // если переход отложенный
                        qstrncat(postfix, "d", sizeof(postfix));
                break;
  }

  OutMnem(8, postfix);


  // по кол-ву операндов бывают такие сочетания в командах:
  // 0, 1, 2, 3 для непараллельных
  // 2+2, 3+2, 3+3, для параллельных

  out_one_operand(0);   //два операнда можно выводить смело
  if ( cmd.Op2.type != o_void )
  {
    out_symbol(',');
    out_one_operand(1);
  }

  gl_comm = 1;                  // generate comments at the next MakeLine();
  if ( cmd.itype2 )             // Is Parallel
  {
        if ( cmd.i2op > 2 ) // 3-й операнд принадлежит первой половине команды
        {
                out_symbol(',');
                out_one_operand(2);
        }
        term_output_buffer();
        MakeLine(buf);
        init_output_buffer(buf, sizeof(buf));

        char insn2[MAXSTR];
        qsnprintf(insn2, sizeof(insn2), "||%s", ph.instruc[uchar(cmd.itype2)].name);
        addblanks(insn2, 8);
        out_line(insn2, COLOR_INSN);


        if ( cmd.i2op == 2 ) // 3-й операнд принадлежит второй половине команды
        {
                out_one_operand(2);
                out_symbol(',');
        }

        if ( cmd.Op4.type != o_void )
        {
                out_one_operand(3);
        }

        if ( cmd.Op5.type != o_void )
        {
                out_symbol(',');
                out_one_operand(4);
        }

        if ( cmd.Op6.type != o_void )
        {
                out_symbol(',');
                out_one_operand(5);
        }
  }
  else
        if ( cmd.Op3.type != o_void )
        {
                out_symbol(',');
                out_one_operand(2);
        }

  if ( isVoid(cmd.ea, uFlag, 0) ) OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea, uFlag, 1) ) OutImmChar(cmd.Op2);
  if ( isVoid(cmd.ea, uFlag, 2) ) OutImmChar(cmd.Op3);

  term_output_buffer();
  MakeLine(buf);
}

//--------------------------------------------------------------------------
static void print_segment_register(int reg, sel_t value)
{
  if ( reg == ph.regDataSreg ) return;
  if ( value != BADADDR )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), value);
    gen_cmt_line("assume %s = %s", ph.regNames[reg], buf);
  }
  else
  {
    gen_cmt_line("drop %s", ph.regNames[reg]);
  }
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
  gen_cmt_line("Processor       : %-8.8s [%s]", inf.procName, device);
  gen_cmt_line("Target assembler: %s", ash.name);
  gen_cmt_line("Byte sex        : %s, %s",
                  inf.mf ? "big-endian" : "little-endian",
                  inf.wide_high_byte_first ? "high_byte_first" : "high_byte_last");
  if ( ash.header != NULL )
    for ( const char **ptr=ash.header; *ptr != NULL; ptr++ )
      printf_line(0,COLSTR("%s",SCOLOR_ASMDIR),*ptr);
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
            COLSTR("%s",SCOLOR_KEYWORD)
            COLSTR("%c%s",SCOLOR_DNUM)
            COLSTR(",",SCOLOR_SYMBOL) " "
            COLSTR("%s",SCOLOR_LOCNAME),
            ash.a_equ,
            sign,
            vstr,
            name);
}
