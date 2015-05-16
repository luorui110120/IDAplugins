
#include "dsp56k.hpp"

//--------------------------------------------------------------------------
static const char * const cc_text[] =
{
  "cc", // carry clear (higher or same) C=0
  "ge", // greater than or equal N Å V=0
  "ne", // not equal Z=0
  "pl", // plus N=0
  "nn", // not normalized Z+(U·E)=0
  "ec", // extension clear E=0
  "lc", // limit clear L=0
  "gt", // greater than Z+(N Å V)=0
  "cs", // carry set (lower) C=1
  "lt", // less than N Å V=1
  "eq", // equal Z=1
  "mi", // minus N=1
  "nr", // normalized Z+(U·E)=1
  "es", // extension set E=1
  "ls", // limit set L=1
  "le", // less than or equal Z+(N Å V)=1
};

//--------------------------------------------------------------------------
static const char * const su_text[] =
{
  "ss", // signed * signed
  "su", // signed * unsigned
  "uu", // unsigned * unsigned
};

static const char * const formats[] =
{
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR(")-", SCOLOR_SYMBOL) COLSTR("n%d", SCOLOR_REG),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR(")+", SCOLOR_SYMBOL) COLSTR("n%d", SCOLOR_REG),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR(")-", SCOLOR_SYMBOL),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR(")+", SCOLOR_SYMBOL),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR(")", SCOLOR_SYMBOL),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR("+", SCOLOR_SYMBOL) COLSTR("n%d", SCOLOR_REG) COLSTR(")", SCOLOR_SYMBOL),
  "internal error with o_phrase",
  COLSTR("-(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR(")", SCOLOR_SYMBOL),
  COLSTR("$+", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("a1", SCOLOR_REG) COLSTR(")", SCOLOR_SYMBOL),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("b1", SCOLOR_REG) COLSTR(")", SCOLOR_SYMBOL),
};
// 0 (Rn)–Nn
// 1 (Rn)+Nn
// 2 (Rn)–
// 3 (Rn)+
// 4 (Rn)
// 5 (Rn+Nn)
// 7 –(Rn)
// 8 $+Rn
// 9 (a1)
// 10 (b1)


static const char * const formats2[] =
{
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR("+", SCOLOR_SYMBOL) COLSTR("$%X", SCOLOR_NUMBER) COLSTR(")", SCOLOR_SYMBOL),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR("-", SCOLOR_SYMBOL) COLSTR("$%X", SCOLOR_NUMBER) COLSTR(")", SCOLOR_SYMBOL),
};


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
  if ( x.type == o_imm         ) out_symbol('#');
  else
  {
    if ( x.amode & amode_x       ) out_register("x"), out_symbol(':');
    if ( x.amode & amode_y       ) out_register("y"), out_symbol(':');
    if ( x.amode & amode_p       ) out_register("p"), out_symbol(':');
    if ( x.amode & amode_l       ) out_register("l"), out_symbol(':');
  }
  if ( x.amode & amode_ioshort ) out_symbol('<'), out_symbol('<');
  if ( x.amode & amode_short   ) out_symbol('<');
  if ( x.amode & amode_long    ) out_symbol('>');
  if ( x.amode & amode_neg     ) out_symbol('-');

  switch ( x.type )
  {
    case o_void:
      return 0;

    case o_imm:
      OutValue(x, OOFS_IFSIGN|OOFW_IMM);
      break;

    case o_reg:
      outreg(x.reg);
      break;

    case o_mem:
      // no break;
    case o_near:
      {
        ea_t ea = calc_mem(x);
        // xmem ioports
        if ( x.amode & (amode_x|amode_l) && out_port_address(x.addr) )
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
        char buf[MAXSTR];
        qsnprintf(buf, sizeof(buf), formats[uchar(x.phtype)], x.phrase, x.phrase);
        out_colored_register_line(buf);
      }
      break;

    case o_displ:
      {
        char buf[MAXSTR];
        qsnprintf(buf, sizeof(buf), formats2[uchar(x.phtype)], x.phrase, x.addr);
        out_colored_register_line(buf);
      }
      break;

    case o_iftype:
      {
        char postfix[4];
        qstrncpy(postfix, cc_text[cmd.auxpref & aux_cc], sizeof(postfix));
        if ( x.imode == imode_if )
          out_snprintf( COLSTR("IF%s", SCOLOR_SYMBOL),  postfix );
        else
          out_snprintf( COLSTR("IF%s.U", SCOLOR_SYMBOL),  postfix );
      }
      break;

    case o_vsltype:
      out_symbol((cmd.auxpref & 1) + '0');
      break;

    default:
      interr("out");
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
static void out_operand_group(int idx, op_t *x, char *bufptr)
{
  for ( int i=0; i < 2; i++,x++ )
  {
    if ( x->type == o_void ) break;
    if ( i )
    {
      out_symbol(',');
    }
    else if ( cmd.itype != DSP56_move || idx != 0 )
    {
      *get_output_ptr() = '\0';   // for tag_strlen
      size_t n = idx == (cmd.itype==DSP56_move) ? tag_strlen(bufptr) : 16;
      do
        OutChar(' ');
      while ( ++n < 20 );
    }
    ph.u_outop(*x);
  }
}

//----------------------------------------------------------------------
void idaapi out(void)
{
  char buf[MAXSTR];
  init_output_buffer(buf, sizeof(buf));

  // output instruction mnemonics
  char postfix[4];
  postfix[0] = '\0';
  switch ( cmd.itype )
  {
    case DSP56_tcc:
    case DSP56_debugcc:
    case DSP56_jcc:
    case DSP56_jscc:
    case DSP56_bcc:
    case DSP56_bscc:
    case DSP56_trapcc:
      qstrncpy(postfix, cc_text[cmd.auxpref & aux_cc], sizeof(postfix));
      break;

    case DSP56_dmac:
    case DSP56_mac_s_u:
    case DSP56_mpy_s_u:
      qstrncpy(postfix, su_text[cmd.auxpref & aux_su], sizeof(postfix));
      break;
  }

  OutMnem(8, postfix);

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

  fill_additional_args();
  for ( int i=0; i < aa.nargs; i++ )
    out_operand_group(i, aa.args[i], buf);

  if ( isVoid(cmd.ea, uFlag, 0) ) OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea, uFlag, 1) ) OutImmChar(cmd.Op2);
  if ( isVoid(cmd.ea, uFlag, 3) ) OutImmChar(cmd.Op3);

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
    const char *predefined[] =
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
    if ( strcmp(sname, "XMEM") == 0 || strcmp(sname, "YMEM") == 0 )
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
      printf_line(inf.indent, COLSTR("section %s", SCOLOR_ASMDIR) " " COLSTR("%s %s", SCOLOR_AUTOCMT),
                   sname,
                   ash.cmnt,
                   sclas);
    }
  }
}

//--------------------------------------------------------------------------
void idaapi assumes(ea_t)                // function to produce assume directives
{
  if ( !inf.s_assume )
    return;
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
    if ( strcmp(sname, "XMEM") != 0 && strcmp(sname, "YMEM") != 0 )
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
      printf_line(0,COLSTR("%s",SCOLOR_ASMDIR),*ptr);
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
void idaapi dsp56k_data(ea_t ea)
{
  intel_data(ea);
}
