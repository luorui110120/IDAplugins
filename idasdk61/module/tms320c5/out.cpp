/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "tms.hpp"

static const char *const phrases[] =
{
  "*",    "*-", "*+", "?",
  "*br0-","*0-","*0+","*br0+"
};

static int hasphrase;
//----------------------------------------------------------------------
inline void OutReg(int rgnum)
{
  out_register(ph.regNames[rgnum]);
}

//----------------------------------------------------------------------
static void OutDecimal(uval_t x)
{
  char buf[40];
  qsnprintf(buf, sizeof(buf), "%" FMT_EA "d", x);
  out_line(buf, COLOR_NUMBER);
}

//----------------------------------------------------------------------
bool is_mpy(void)
{
  switch ( cmd.itype )
  {
    case TMS_mpy:       // Multiply
    case TMS_mpya:      // Multiply and Accumulate Previous Product
    case TMS_mpys:      // Multiply and Subtract Previous Product
    case TMS2_mpy:      // Multiply (with T register, store product in P register)
    case TMS2_mpya:     // Multiply and accumulate previous product
    case TMS2_mpyk:     // Multiply immediate
    case TMS2_mpys:     // Multiply and subtract previous product
      return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool idaapi outop(op_t &x)
{
  switch ( x.type )
  {
  case o_reg:
        OutReg(x.reg);
        break;
  case o_phrase:
        out_line(phrases[x.phrase>>4],COLOR_SYMBOL);
        hasphrase = 1;
        break;
  case o_imm:
        switch ( x.sib ) {
          default:
            {
              if ( !isC2() ) out_symbol('#');
              flags_t saved = uFlag;
              if ( !isDefArg(uFlag,x.n)
                   && (is_mpy() || is_invsign(cmd.ea, uFlag, x.n))
                 ) uFlag |= decflag();
              OutValue(x,OOFW_16|(is_mpy() ? OOF_SIGNED : 0));
              uFlag = saved;
            }
            break;
          case 1:
            OutValue(x,OOF_NUMBER|OOFS_NOSIGN);
            break;
          case 2:
//            if ( x.value == 0 ) return 0;
            OutDecimal(x.value);
            break;
          case 3:
            OutDecimal(x.value);
            break;
        }
        break;
  case o_near:
        if ( cmd.itype == TMS_blpd ) out_symbol('#');
  case o_mem:
        {
          if ( cmd.itype == TMS_bldd && x.sib ) out_symbol('#');
          ea_t base = (x.type == o_mem)
                        ? dataSeg_op(x.n)
                        : codeSeg(x.addr,x.n);
          ea_t v = toEA(base,x.addr);
          bool rptb_tail = false;
          if ( cmd.itype == TMS_rptb && isTail(get_flags_novalue(v)) )
          {
            // small hack to display end_loop-1 instead of before_end_loop+1
            v++;
            x.addr++;
            rptb_tail = true;
          }
          bool ok = out_name_expr(x, v, x.addr);
          if ( rptb_tail ) x.addr--;
          if ( !ok )
          {
            OutValue(x, OOF_ADDR|OOF_NUMBER|OOFS_NOSIGN|OOFW_16);
            QueueMark(Q_noName, cmd.ea);
          }
          else
          {
            if ( rptb_tail )
            {
              out_symbol('-');
              out_line("1", COLOR_NUMBER);
            }
          }
        }
        break;
  case o_void:
        return 0;
  case o_bit:
        {
          static const char *const bitnames[] =
          {
            "intm","ovm","cnf","sxm",
            "hm","tc","xf","c"
          };
          out_keyword(bitnames[uchar(x.value)]);
        }
        break;
  case o_cond:
        {
          int mask = int(x.value>>0) & 0xF;
          int cond = int(x.value>>4) & 0xF;
          int comma = 1;
          out_tagon(COLOR_KEYWORD);
          switch ( (mask>>2) & 3 )      // Z L
          {
            case 0:
              comma = 0;
              break;
            case 1:
              OutLine( (cond>>2)&1 ? "lt" : "gt" );
              break;
            case 2:
              OutLine( (cond>>2)&2 ? "eq" : "neq" );
              break;
            case 3:
              switch( (cond>>2)&3 )
              {
                case 2: OutLine("geq"); break;
                case 3: OutLine("leq"); break;
              }
              break;
          }
          if ( mask & 1 )               // C
          {
            if ( comma ) OutChar(',');
            if ( (cond & 1) == 0 ) OutChar('n');
            OutChar('c');
            comma = 1;
          }
          if ( mask & 2 )               // V
          {
            if ( comma ) OutChar(',');
            if ( (cond & 2) == 0 ) OutChar('n');
            OutChar('o');
            OutChar('v');
            comma = 1;
          }
          static const char *const TP[] = { "bio","tc","ntc",NULL };
          const char *ptr = TP[int(x.value>>8) & 3];
          if ( ptr != NULL )
          {
            if ( comma )
              OutChar(',');
            OutLine(ptr);
          }
          out_tagoff(COLOR_KEYWORD);
        }
        break;
  default:
        warning("out: %a: bad optype %d",cmd.ea,x.type);
        break;
  }
  return 1;
}

//----------------------------------------------------------------------
static int outnextar(op_t &o,int comma)
{
  if ( o.type == o_phrase && (o.phrase & 8) != 0 )
  {
    if ( comma )
    {
      out_symbol(',');
      OutChar(' ');
    }
    OutReg(rAr0+(o.phrase&7));
    return 1;
  }
  return 0;
}

//----------------------------------------------------------------------
static int isDelayed(ushort code)
{
// 7D?? BD    0111 1101 1AAA AAAA + 1  Branch unconditional with AR update delayed
// 7E?? CALLD 0111 1110 1AAA AAAA + 1  Call unconditional with AR update delayed
// 7F?? BANZD 0111 1111 1AAA AAAA + 1  Branch AR=0 with AR update delayed
// BE3D CALAD 1011 1110 0011 1101      Call subroutine addressed by ACC delayed
// BE21 BACCD 1011 1110 0010 0001      Branch addressed by ACC delayed
// FF00 RETD  1111 1111 0000 0000      Return, delayed
// F??? CCD   1111 10TP ZLVC ZLVC + 1  Call conditional delayed
// F??? RETCD 1111 11TP ZLVC ZLVC      Return conditional delayed
// F??? BCNDD 1111 00TP ZLVC ZLVC + 1  Branch conditional delayed
  ushort subcode;
  switch ( code>>12 ) {
    case 7:
      subcode = (code >> 7);
      return subcode == 0xFB || subcode == 0xFD || subcode == 0xFF;
    case 0xB:
      return code == 0xBE21u || code == 0xBE3Du;
    case 0xF:
      if ( code == 0xFF00 ) return 1;
      subcode = (code & 0x0C00);
      return subcode != 0x400;
  }
  return 0;
}

//----------------------------------------------------------------------
ea_t prevInstruction(ea_t ea)
{
  ea--;
  if ( !isCode(get_flags_novalue(ea)) )
    ea--;
  return ea;
}

//inline int isXC2(ushort code) { return (code & 0xFC00) == 0xF400; }
//----------------------------------------------------------------------
static int shouldIndent(void)
{
  if ( isC2() ) return 0;                       // TMS320C2 - no indention
  if ( !isFlow(uFlag) ) return 0;               // no previous instructions
  ea_t ea = prevInstruction(cmd.ea);
  flags_t F = get_flags_novalue(ea);
  if ( !isCode(F) ) return 0;
  if ( isDelayed((ushort)get_full_byte(ea)) ) return 1;
  if ( cmd.size == 2 )                          // our instruction is long
  {
//    if ( isXC2(get_full_byte(prevInstruction(ea))) ) return 1;
    ; // nothing to do
  }
  else
  {                                             // our instruction short
    if ( (cmd.ea-ea) == 2 )                     // prev instruction long
      return 0;                                 // can't be executed in delayed manner
    if ( !isFlow(F) ) return 0;                 // no prev instr...
    ea = prevInstruction(ea);
    F = get_flags_novalue(ea);
  }
  return isCode(F) && isDelayed((ushort)get_full_byte(ea));
}


//----------------------------------------------------------------------
static void outphraseAr(void)
{
  ea_t ar;
  if ( find_ar(&ar) )
  {
    char buf[MAXSTR];
    ea2str(ar, buf, sizeof(buf));
    out_snprintf(COLSTR(" %s(%s)",SCOLOR_AUTOCMT), ash.cmnt, buf);
  }
}

//----------------------------------------------------------------------
static void OutImmVoid(op_t &x)
{
  static int tmsfunny = -1;
  if ( tmsfunny == -1 ) tmsfunny = (getenv("TMSFIX") != 0);
  if ( !tmsfunny ) return;
  if ( x.type == o_imm )
  {
    if ( x.value != 0 )
    {
      int v = int(short(x.value) * 10000L / 0x7FFF);
      OutChar(' ');
      out_tagon(COLOR_AUTOCMT);
      OutLine(ash.cmnt);
      OutChar(' ');
      if ( v < 0 )
      {
        OutChar('-');
        v = -v;
      }
      char buf[10];
      if ( v == 10000 )
        qstrncpy(buf, "1.0000", sizeof(buf));
      else
        qsnprintf(buf, sizeof(buf), "0.%04d", v);
      OutLine(buf);
      out_tagoff(COLOR_AUTOCMT);
    }
  }
}

//----------------------------------------------------------------------
void idaapi out(void)
{
  char buf[MAXSTR];

  hasphrase = 0;

  init_output_buffer(buf, sizeof(buf));
  if ( shouldIndent() ) OutChar(' ');
  OutMnem();

  int comma = cmd.Op1.showed() && out_one_operand(0);

  if ( cmd.Op2.showed() && cmd.Op2.type != o_void )
  {
    if ( comma )
    {
      out_tagon(COLOR_SYMBOL);
      OutChar(',');
      out_tagoff(COLOR_SYMBOL);
      OutChar(' ');
    }
    out_one_operand(1);
  }

  if ( cmd.Op1.type == o_phrase ) comma |= outnextar(cmd.Op1,comma);
  if ( cmd.Op2.type == o_phrase )          outnextar(cmd.Op2,comma);

  if ( isVoid(cmd.ea,uFlag,0) ) OutImmVoid(cmd.Op1);
  if ( isVoid(cmd.ea,uFlag,1) ) OutImmVoid(cmd.Op2);

  if ( hasphrase ) outphraseAr();

  term_output_buffer();
  gl_comm = 1;
  MakeLine(buf);
}

//--------------------------------------------------------------------------
void idaapi header(void)
{
  int ps = sizeof(inf.procName);
  gen_cmt_line("Processor:        %-*.*s", ps, ps, inf.procName);
  gen_cmt_line("Target assembler: %s",ash.name);
  if ( ash.header != NULL )
    for ( const char **ptr=ash.header; *ptr != NULL; ptr++ )
      printf_line(0,COLSTR("%s",SCOLOR_ASMDIR),*ptr);
}

//--------------------------------------------------------------------------
void idaapi segstart(ea_t ea)
{
  segment_t *Sarea = getseg(ea);
  char sname[MAXNAMELEN];
  get_segm_name(Sarea, sname, sizeof(sname));

  printf_line(inf.indent, COLSTR(".sect \"%s\"",SCOLOR_ASMDIR), sname);
  if ( inf.s_org )
  {
    ea_t org = ea - get_segm_base(Sarea);
    if ( org != 0 )
    {
      char buf[MAX_NUMBUF];
      btoa(buf, sizeof(buf), org);
      printf_line(inf.indent, COLSTR("%s .org %s",SCOLOR_AUTOCMT),
                  ash.cmnt, buf);
    }
  }
}

//--------------------------------------------------------------------------
void idaapi footer(void)
{
  char buf[MAXSTR];
  char *const end = buf + sizeof(buf);
  if ( ash.end != NULL )
  {
    MakeNull();
    char *ptr = tag_addstr(buf, end, COLOR_ASMDIR, ash.end);
    char name[MAXSTR];
    if ( get_colored_name(BADADDR, inf.beginEA, name, sizeof(name)) != NULL )
    {
      APPCHAR(ptr, end, ' ');
      APPEND(ptr, end, name);
    }
    MakeLine(buf, inf.indent);
  }
  else
  {
    gen_cmt_line("end of file");
  }
}

//--------------------------------------------------------------------------
void idaapi tms_assumes(ea_t ea)
{
  segreg_t *Darea  = getSRarea(ea);
  segment_t *Sarea = getseg(ea);

  if ( Sarea == NULL || Darea == NULL ||
       Sarea->type == SEG_XTRN ||
       Sarea->type == SEG_DATA ||
       !inf.s_assume ) return;

  int show = (ea == Sarea->startEA);
  if ( show || Darea->startEA == ea ) {
    segreg_t our         = *Darea;
    segreg_t *prev = show ? NULL : getSRarea(ea-1);
    if ( prev == NULL || prev->reg(rDP) != our.reg(rDP) )
      printf_line(inf.indent,COLSTR("%s --- assume DP %04a",SCOLOR_AUTOCMT), ash.cmnt, our.reg(rDP));
  }
}
