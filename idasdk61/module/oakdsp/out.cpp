
#include "oakdsp.hpp"
#include <frame.hpp>
#include <srarea.hpp>
#include <struct.hpp>



//--------------------------------------------------------------------------
static const char * const cc_text[] =
{
  "",          //Always
  "eq",        //Equal to zero Z = 1
  "neq",       //Not equal to zero Z = 0
  "gt",        //Greater than zero M = 0 and Z = 0
  "ge",        //Greater than or equal to zero M = 0
  "lt",        //Less than zero M =1
  "le",        //Less than or equal to zero M = 1 or Z = 1
  "nn",        //Normalized flag is cleared N = 0
  "v",         //Overflow flag is set V = 1
  "c",         //Carry flag is set C = 1
  "e",         //Extension flag is set E = 1
  "l",         //Limit flag is set L = 1
  "nr",        //flag is cleared R = 0
  "niu0",      //Input user pin 0 is cleared
  "iu0",       //Input user pin 0 is set
  "iu1",       //Input user pin 1 is set

};


static const char * const formats[] =
{
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR(")", SCOLOR_SYMBOL),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR(")+1", SCOLOR_SYMBOL),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR(")-1", SCOLOR_SYMBOL),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR(")+s", SCOLOR_SYMBOL),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("reg", SCOLOR_REG) COLSTR(")", SCOLOR_SYMBOL),
};

//0 (Rn)
//1 (Rn)+1
//2 (Rn)-1
//3 (Rn)+s
//4 (any_reg)

static const char * const formats2[] =
{
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("rb+#", SCOLOR_REG),
  COLSTR("#", SCOLOR_REG),
};
//0 (rb + #)
//1 #

static const char * const swap_formats[] =
{
        COLSTR("(a0, b0)", SCOLOR_REG),
        COLSTR("(a0, b1)", SCOLOR_REG),
        COLSTR("(a1, b0)", SCOLOR_REG),
        COLSTR("(a1, b1)", SCOLOR_REG),
        COLSTR("(a0, b0), (a1, b1)", SCOLOR_REG),
        COLSTR("(a0, b1), (a1, b0)", SCOLOR_REG),
        COLSTR("(a0, b0, a1)", SCOLOR_REG),
        COLSTR("(a0, b1, a1)", SCOLOR_REG),
        COLSTR("(a1, b0, a0)", SCOLOR_REG),
        COLSTR("(a1, b1, a0)", SCOLOR_REG),
        COLSTR("(b0, a0, b1)", SCOLOR_REG),
        COLSTR("(b0, a1, b1)", SCOLOR_REG),
        COLSTR("(b1, a0, b0)", SCOLOR_REG),
        COLSTR("(b1, a1, b0)", SCOLOR_REG),
};

//(a0, b0)
//(a0, b1)
//(a1, b0)
//(a1, b1)
//(a0, b0), (a1, b1)
//(a0, b1), (a1, b0)
//(a0, b0, a1)
//(a0, b1, a1)
//(a1, b0, a0)
//(a1, b1, a0)
//(b0, a0, b1)
//(b0, a1, b1)
//(b1, a0, b0)
//(b1, a1, b0)

//----------------------------------------------------------------------
static bool out_port_address(ea_t addr)
{
  const char *name = find_port(addr);
  if ( name != NULL )
  {
    out_line(name, COLOR_IMPNAME);
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
static void out_bad_address(ea_t addr)
{
  if ( !out_port_address(addr) )
  {
    out_tagon(COLOR_ERROR);
    OutLong(addr, 16);
    out_tagoff(COLOR_ERROR);
    QueueMark(Q_noName, cmd.ea);
  }
}

//----------------------------------------------------------------------
static void out_address(ea_t ea, op_t &x)
{

    if ( !out_name_expr(x, ea,/* ea */ BADADDR) )
    {
          out_tagon(COLOR_ERROR);
          OutValue(x, OOFW_IMM|OOF_ADDR|OOFW_16);
          out_snprintf(" (ea = %a)", ea);
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
inline void out_ip_rel(int displ)
{
  out_snprintf(COLSTR("%s+", SCOLOR_SYMBOL) COLSTR("%d", SCOLOR_NUMBER),
              ash.a_curip, displ);
}

//----------------------------------------------------------------------
bool idaapi outop(op_t &x)
{
  ea_t ea;
  char buf[MAXSTR];

  if ( x.type == o_imm ) out_symbol('#');

  switch ( x.type )
  {
    case o_void:
      return 0;

    case o_imm:
      if ( x.amode & amode_signed )
              OutValue(x, OOF_SIGNED|OOFW_IMM);
      else
              OutValue(x, OOFS_IFSIGN|OOFW_IMM);
      break;

    case o_reg:
      outreg(x.reg);
      break;

    case o_mem:
      // no break;
      ea = calc_mem(x);
      if ( ea != BADADDR )
        out_address(ea, x);
      else
      {
        out_tagon(COLOR_ERROR);
        OutValue(x, OOFW_IMM|OOF_ADDR|OOFW_16);
        out_tagoff(COLOR_ERROR);
      }
      break;

    case o_near:
      {
        ea_t ea = calc_mem(x);
        // xmem ioports
        if ( x.amode & (amode_x) && out_port_address(x.addr) )
        {
          char nbuf[MAXSTR];
          const char *pnam = find_port(x.addr);
          const char *name = get_true_name(BADADDR, ea, nbuf, sizeof(nbuf));
          if ( name == NULL || strcmp(name, pnam) != 0 )
            set_name(ea, pnam);
          break;
        }
        if ( ea == cmd.ea+cmd.size )
          out_ip_rel(cmd.size);
        else if ( !out_name_expr(x, ea, x.addr) )
          out_bad_address(x.addr);
      }
      break;

    case o_phrase:
      {
        if ( x.phtype < 4 )
        {
                qsnprintf(buf, sizeof(buf), formats[uchar(x.phtype)], x.phrase);
                out_colored_register_line(buf);
        }
        if ( x.phtype == 4 )
        {
                out_symbol('(');
                outreg(x.reg);
                out_symbol(')');
        }
      }
      break;

    case o_local:
      {
        out_colored_register_line(formats2[uchar(x.phtype)]);
        OutValue(x, OOF_SIGNED|OOF_ADDR);
        if ( x.phtype == 0 )
          out_symbol(')');
        break;
      }

    case o_textphrase:
      {
        char buf[MAXSTR];

              switch ( x.textphtype )
              {
                case text_swap:
                        out_line(swap_formats[x.phrase], COLOR_REG);
                        break;

                case text_banke:

                        int comma;
                        char r0[10], r1[10], r4[10], cfgi[10];
                        comma = 0;


                        r0[0]=r1[0]=r4[0]=cfgi[0]='\0';

                        if ( x.phrase & 0x01 ) //cfgi
                        {
                                qsnprintf(cfgi, sizeof(cfgi), "cfgi");
                                comma = 1;
                        }

                        if ( x.phrase & 0x02 ) //r4
                        {
                                qsnprintf(r4, sizeof(r4), "r4%s", (comma?", ":""));
                                comma = 1;
                        }

                        if ( x.phrase & 0x04 ) //r1
                        {
                                qsnprintf(r1, sizeof(r1), "r1%s", (comma?", ":""));
                                comma = 1;
                        }

                        if ( x.phrase & 0x08 ) //r0
                                qsnprintf(r0, sizeof(r0), "r0%s", (comma?", ":""));

                        qsnprintf(buf, sizeof(buf), "%s%s%s%s", r0, r1, r4, cfgi );
                        out_line(buf, COLOR_REG);

                        break;
                case text_cntx:
                        out_symbol( (x.phrase ? 'r': 's') );
                        break;
                case text_dmod:
                        if ( x.phrase )
                                qsnprintf(buf, sizeof(buf), " no modulo");
                        else
                                qsnprintf(buf, sizeof(buf), " modulo");

                        out_line(buf, COLOR_REG);

                        break;
                case text_eu:
                        qsnprintf(buf, sizeof(buf), " eu");
                        out_line(buf, COLOR_REG);
                        break;
              }

      }
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

  // output instruction mnemonics
  char postfix[10];
  postfix[0] = '\0';

  OutMnem(8);

  bool comma = out_one_operand(0);
  if ( cmd.Op2.type != o_void )
  {
    if ( comma ) out_symbol(',');
    out_one_operand(1);
  }
  if ( cmd.Op3.type != o_void )
  {
    out_symbol(',');
    out_one_operand(2);
  }




  if ( isVoid(cmd.ea, uFlag, 0) ) OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea, uFlag, 1) ) OutImmChar(cmd.Op2);
  if ( isVoid(cmd.ea, uFlag, 3) ) OutImmChar(cmd.Op3);

  switch ( cmd.itype )
  {
    case OAK_Dsp_callr:
    case OAK_Dsp_ret:
    case OAK_Dsp_br:
    case OAK_Dsp_call:
    case OAK_Dsp_reti:
    case OAK_Dsp_brr:
    case OAK_Dsp_shfc:
    case OAK_Dsp_shr:
    case OAK_Dsp_shr4:
    case OAK_Dsp_shl:
    case OAK_Dsp_shl4:
    case OAK_Dsp_ror:
    case OAK_Dsp_rol:
    case OAK_Dsp_clr:
    case OAK_Dsp_not:
    case OAK_Dsp_neg:
    case OAK_Dsp_rnd:
    case OAK_Dsp_pacr:
    case OAK_Dsp_clrr:
    case OAK_Dsp_inc:
    case OAK_Dsp_dec:
    case OAK_Dsp_copy:
    case OAK_Dsp_maxd:
    case OAK_Dsp_max:
    case OAK_Dsp_min:
            qsnprintf(postfix, sizeof(postfix), "%s%s%s", ( (cmd.auxpref & aux_comma_cc) ? ", ": ""), \
            cc_text[cmd.auxpref & aux_cc], \
            ( (cmd.auxpref & aux_iret_context) ? ", context": "") );
            out_line(postfix, COLOR_REG);
            break;
  }

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
  char sclas[MAXNAMELEN];
  get_true_segm_name(Sarea, sname, sizeof(sname));
  get_segm_class(Sarea, sclas, sizeof(sclas));

  if ( ash.uflag & UAS_GNU )
  {
    const char *const predefined[] =
    {
      ".text",    // Text section
      ".data",    // Data sections
      ".rdata",
      ".comm",
    };

    int i;
    for ( i=0; i < qnumber(predefined); i++ )
      if ( strcmp(sname, predefined[i]) == 0 )
        break;
    if ( i != qnumber(predefined) )
      printf_line(inf.indent, COLSTR("%s", SCOLOR_ASMDIR), sname);
    else
      printf_line(inf.indent, COLSTR(".section %s", SCOLOR_ASMDIR) " " COLSTR("%s %s", SCOLOR_AUTOCMT),
                   sname,
                   ash.cmnt,
                   sclas);
  }
  else
  {
    if ( strcmp(sname, "XMEM") == 0 )
    {
      char buf[MAX_NUMBUF];
      btoa(buf, sizeof(buf), ea-get_segm_base(Sarea));
      printf_line(inf.indent, COLSTR("%s %c:%s", SCOLOR_ASMDIR),
                  ash.origin,
                  qtolower(sname[0]),
                  buf);
    }
    else
    {
      printf_line(inf.indent, COLSTR("section %s", SCOLOR_ASMDIR) " "
                              COLSTR("%s %s", SCOLOR_AUTOCMT),
                  sname,
                  ash.cmnt,
                  sclas);
    }
  }
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
void idaapi segend(ea_t ea)
{
  segment_t *Sarea = getseg(ea-1);
  if ( is_spec_segm(Sarea->type) ) return;
  if ( (ash.uflag & UAS_GNU) == 0 )
  {
    char sname[MAXNAMELEN];
    get_true_segm_name(Sarea, sname, sizeof(sname));
    if ( strcmp(sname, "XMEM") != 0 )
      printf_line(inf.indent, "endsec");
  }
}

//--------------------------------------------------------------------------
void idaapi header(void)
{
  gen_cmt_line("Processor       : %-8.8s [%s]", inf.procName, device);
  gen_cmt_line("Target assembler: %s", ash.name);
  gen_cmt_line("Byte sex        : %s", inf.mf ? "Big endian" : "Little endian");
  if ( ash.header != NULL )
    for ( const char **ptr=ash.header; *ptr != NULL; ptr++ )
      printf_line(0, COLSTR("%s",SCOLOR_ASMDIR),*ptr);
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

//--------------------------------------------------------------------------
void idaapi oakdsp_data(ea_t ea)
{
  intel_data(ea);
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
  get_member_name(mptr->id, name, sizeof(name));
  char vstr[MAX_NUMBUF];
  btoa(vstr, sizeof(vstr), v);
  qsnprintf(buf, bufsize,
            COLSTR("%s",SCOLOR_KEYWORD) " "
            COLSTR("%c%s",SCOLOR_DNUM)
            COLSTR(",",SCOLOR_SYMBOL) " "
            COLSTR("%s",SCOLOR_LOCNAME),
            ash.a_equ,
            sign,
            vstr,
            name);
}
