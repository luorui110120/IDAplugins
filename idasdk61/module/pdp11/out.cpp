/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      PDP11 module.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#include "pdp.hpp"

//----------------------------------------------------------------------
inline void OutReg(int rgnum)
{
  out_register(ph.regNames[rgnum]);
}

//----------------------------------------------------------------------
bool idaapi outop(op_t &x) {
  ea_t segadr;
  switch ( x.type ) {
  case o_void:
    return 0;
  case o_reg:
    OutReg(x.reg);
        break;
  case o_fpreg:
    OutReg(x.reg + 8);
    break;
  case o_imm:            // 27
    if ( x.ill_imm ) {
      out_symbol('(');
      OutReg(rPC);
      out_symbol(')');
      out_symbol('+');
    } else {
      out_symbol('#');
      if ( x.dtyp == dt_float || x.dtyp == dt_double ) {
        char str[MAXSTR];
        if ( out_real(&x.value, 2, str, sizeof(str)) ) {
          register char *p = str;
          while ( *p == ' ' ) p++;
          out_symbol('^');
          out_symbol('F');
          out_line(p, COLOR_NUMBER);
        } else out_long(x.value, 8);
      } else OutValue(x, OOF_SIGNED | OOFW_IMM);
    }
    break;
  case o_mem:            // 37/67/77
  case o_near:      // jcc/ [jmp/call 37/67]
  case o_far:
    if ( x.phrase != 0 ) {
      if ( x.phrase == 077 || x.phrase == 037) out_symbol('@' );
      if ( x.phrase == 037) out_symbol('#' );
      if ( x.addr16 < m.asect_top && !isOff(uFlag,x.n) ) {
        OutValue(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_16);
        break;
      }
    }
    segadr = toEA(x.type == o_far ? x.segval : codeSeg(x.addr16,x.n), x.addr16);
    if ( !out_name_expr(x, segadr, x.addr16) ) {
       if ( x.type == o_far || x.addr16 < 0160000 )
                                              QueueMark(Q_noName, cmd.ea);
       OutValue(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_16);
    }
    break;
  case o_number:      //EMT/TRAP/MARK/SPL
    OutValue(x, OOF_NUMBER | OOFS_NOSIGN | OOFW_8);
    break;
  case o_displ:           // 6x/7x (!67/!77)
    if ( x.phrase >= 070) out_symbol('@' );
    OutValue(x, OOF_ADDR | OOF_SIGNED | OOFW_16);
    out_symbol('(');
    goto endregout;
  case o_phrase:         // 1x/2x/3x/4x/5x (!27/!37)
    switch ( x.phrase >> 3 ) {
       case 1:
         out_symbol('@');
         OutReg(x.phrase & 7);
         break;
       case 3:
         out_symbol('@');
       case 2:
         out_symbol('(');
         OutReg(x.phrase & 7);
         out_symbol(')');
         out_symbol('+');
         break;
       case 5:
         out_symbol('@');
       case 4:
         out_symbol('-');
         out_symbol('(');
endregout:
         OutReg(x.phrase & 7);
         out_symbol(')');
         break;
    }
    break;
  default:
  warning("out: %" FMT_EA "o: bad optype %d", cmd.ip, x.type);
        break;
  }
  return 1;
}

//----------------------------------------------------------------------
void idaapi out(void) {
  char buf[MAXSTR];
  static const char *const postfix[] = { "", "b"};
  init_output_buffer(buf, sizeof(buf));

  OutMnem(8, postfix[cmd.bytecmd]);
  if ( cmd.itype == pdp_compcc ) {
    uint i = 0, code, first = 0;
    static uint tabcc[8] = {pdp_clc, pdp_clv, pdp_clz, pdp_cln,
                            pdp_sec, pdp_sev, pdp_sez, pdp_sen};
    code = cmd.Op1.phrase;
    out_symbol('<');
    if ( code >= 020 ) {
      if ( (code ^= 020) == 0) OutLine(COLSTR("nop!^O20", SCOLOR_INSN) );
      i = 4;
    }
    for( ; code; i++, code >>= 1) if ( code & 1 ) {
      if ( first++) out_symbol('!' );
      out_line(ph.instruc[tabcc[i]].name, COLOR_INSN);
    }
    out_symbol('>');
  }

  out_one_operand(0);

  if ( cmd.Op2.type != o_void ) {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(1);
  }

  if ( isVoid(cmd.ea, uFlag, 0)) OutImmChar(cmd.Op1 );
  if ( isVoid(cmd.ea, uFlag, 1)) OutImmChar(cmd.Op2 );

  term_output_buffer();
  gl_comm = 1;
  MakeLine(buf);
}

//--------------------------------------------------------------------------
void idaapi header(void) {
  gen_cmt_line("Processor:        %s", inf.procName);
  gen_cmt_line("Target assembler: %s", ash.name);
  if ( ash.header != NULL  )
    for (const char **ptr=ash.header; *ptr != NULL; ptr++ ) MakeLine(*ptr, 0);
}

//--------------------------------------------------------------------------
void idaapi segstart(ea_t ea)
{
  char buf[MAXSTR];
  char *const end = buf + sizeof(buf);
  segment_t *Sarea = getseg(ea);

  if ( Sarea->type == SEG_IMEM)
  {
    MakeLine(COLSTR(".ASECT", SCOLOR_ASMDIR), inf.indent);
  }
  else
  {
    char sname[MAXNAMELEN];
    get_segm_name(Sarea, sname, sizeof(sname));
    char *p = buf + qsnprintf(buf, sizeof(buf),
                              COLSTR(".PSECT %s", SCOLOR_ASMDIR),
                              sname);
    if ( Sarea->ovrname != 0 )
    {
       char bseg[MAX_NUMBUF];
       char breg[MAX_NUMBUF];
       btoa(bseg, sizeof(bseg), Sarea->ovrname & 0xFFFF, 10);
       btoa(breg, sizeof(breg), Sarea->ovrname >> 16, 10);
       qsnprintf(p, end-p,
               COLSTR(" %s Overlay Segment %s, Region %s", SCOLOR_AUTOCMT),
               ash.cmnt, bseg, breg);
    }
    MakeLine(buf, 0);
  }

  if ( inf.s_org ) {
    size_t org = size_t(ea-get_segm_base(Sarea));
    if ( org != 0 && org != m.asect_top && Sarea->comorg()  ) {
       char *p = tag_on(buf, end, COLOR_ASMDIR);
       APPEND(p, end, ash.origin);
       APPEND(p, end, ash.a_equ);
       if ( Sarea->type != SEG_IMEM ) {
          APPEND(p, end, ash.origin);
          APPCHAR(p, end, '+');
       }
       p += btoa(p, end-p, org);
       tag_off(p, end, COLOR_ASMDIR);
       MakeLine(buf, inf.indent);
    }
  }
}

//--------------------------------------------------------------------------
void idaapi footer(void) {
  char buf[MAXSTR];
  char *const end = buf + sizeof(buf);
  if ( ash.end != NULL ) {
    MakeNull();
    char *p = tag_addstr(buf, end, COLOR_ASMDIR, ash.end);
    char name[MAXSTR];
    if ( get_colored_name(BADADDR, inf.beginEA, name, sizeof(name)) != NULL )
    {
      register size_t i = strlen(ash.end);
      do APPCHAR(p, end, ' '); while ( ++i < 8 );
      APPEND(p, end, name);
    }
    MakeLine(buf, inf.indent);
  } else gen_cmt_line("end of file");
}

//--------------------------------------------------------------------------
static int out_equ(ea_t ea) {
  segment_t *s = getseg(ea);
  char buf[MAXSTR];
  if ( s != NULL ) {
    if ( s->type != SEG_IMEM && !isLoaded(ea) ) {
      char num[MAX_NUMBUF];
      btoa(num, sizeof(num), get_item_size(ea));
      qsnprintf(buf, sizeof(buf), ash.a_bss, num);
      gl_name = 1;
      MakeLine(buf);
      return(1);
    }
  }
  return(0);
}

//--------------------------------------------------------------------------
void idaapi pdp_data(ea_t ea)
{
  char buf[MAXSTR];
  char *const end = buf + sizeof(buf);
  ushort v[5];
  ea_t endea;
  register char *p;
  register ushort i, j;

  if ( out_equ(ea) ) return;

  i = 0;
  if ( !isUnknown(uFlag) ) {
    if ( isWord(uFlag) && getRadix(uFlag,0) == 16 ) i = 2;
    else if ( isDwrd(uFlag) ) i = 4;
         else if ( isQwrd(uFlag) ) i = 8;
              else if ( isTbyt(uFlag) ) i = 10;
    if ( !i ) {
      intel_data(ea);
      return;
    }

    gl_name = 1;
    for(endea = get_item_end(ea); ea < endea; ea += i ) {
      color_t ntag;
      p = tag_addstr(buf, end, COLOR_KEYWORD, ".rad50  ");
      p = tag_on(p, end, ntag = COLOR_CHAR);
      APPCHAR(p, end, '/');
      memset(v, 0, sizeof(v));
      if ( !get_many_bytes(ea, v, i) || r50_to_asc(v, p, i/2) != 0  ) {
        p = tag_addstr(buf, end, COLOR_KEYWORD, ".word   ");
        p = tag_on(p, end, ntag = COLOR_NUMBER);
        for(j = 0; j < i/2; j++ ) {
          if ( i) APPCHAR(p, end, ',' );
          p += btoa(p, end-p, v[j], getRadix(uFlag, 0));
        }
      } else {
        p = tail(p);
        APPCHAR(p, end, '/');
      }
      tag_off(p, end, ntag);
      if ( MakeLine(buf) ) return;   // too many lines
    }
    return;
  }
// unknown
  gl_name = 1;
  if ( !isLoaded(ea)) MakeLine(COLSTR(".blkb", SCOLOR_KEYWORD) );
  else {
    ushort  w;
    uchar   c = get_byte(ea),  c1;

    c1 = (c >= ' ' && ash.XlatAsciiOutput != 0) ? ash.XlatAsciiOutput[c] : c;

    char cbuf[MAX_NUMBUF];
    btoa(cbuf, sizeof(cbuf), c);
    p = buf + qsnprintf(buf, sizeof(buf),
                        COLSTR(".byte ", SCOLOR_KEYWORD)
                        COLSTR("%4s ", SCOLOR_DNUM)
                        COLSTR("%s %c", SCOLOR_AUTOCMT),
                        cbuf, ash.cmnt, c1 >= ' ' ? c1 : ' ');
    if ( !(ea & 1) && (i = get_word(ea)) != 0 ) {
       p = tag_on(p, end, COLOR_AUTOCMT);
       APPCHAR(p, end, ' ');
       b2a32(i, p, end-p, 2, 0);
       p = tail(p);
       APPCHAR(p, end, ' ');
       w = i;
       r50_to_asc(&w, p, 1);
       p = tail(p);
       tag_off(p, end, COLOR_AUTOCMT);
    }
    MakeLine(buf);
  } // undefined

}

//--------------------------------------------------------------------------
