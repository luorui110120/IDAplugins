/*
 *      Interactive disassembler (IDA).
 *      Version 2.06
 *      Copyright (c) 1990-93 by Ilfak Guilfanov. (2:5020/209@fidonet)
 *      ALL RIGHTS RESERVED.
 *
 */

#include "i5.hpp"

//----------------------------------------------------------------------
static const char *const condNames[] =
{
  "nz",
  "z",
  "nc",
  "c",
  "po",
  "pe",
  "p",
  "m"
};

//----------------------------------------------------------------------
inline bool isFunny(void) { return (ash.uflag & UAS_FUNNY); }

//----------------------------------------------------------------------
static void OutReg(int rgnum) {
  if ( (ash.uflag & UAS_NPAIR) != 0 ) {
    switch ( rgnum ) {
      case R_bc: out_register(ph.regNames[R_b]); return;
      case R_de: out_register(ph.regNames[R_d]); return;
      case R_hl: out_register(ph.regNames[R_h]); return;
    }
  }
  if ( rgnum == R_af && isZ80() && !isFunny() ) out_register("af");
  else out_register(ph.regNames[rgnum]);
}

//----------------------------------------------------------------------
bool idaapi i5_outop(op_t &x)
{
  if ( !x.showed() ) return 0;

  switch ( x.type )
  {
  case o_cond:

        if ( x.Cond == oc_not ) return 0;
        {
          char buf[3];
          qstrncpy(buf, condNames[ x.Cond ], sizeof(buf));
          if ( ash.uflag & UAS_CNDUP ) strupr(buf);
          out_keyword(buf);
        }
        break;

  case o_reg:

        OutReg(x.reg);
        break;

  case o_displ:         // Z80 only!!! + GB, one instruction
        if ( ash.uflag & UAS_MKOFF ) OutValue(x,OOF_ADDR|OOFW_16);
        if ( !isGB() ) out_symbol('(');
        OutReg(x.phrase);
        if ( !(ash.uflag & UAS_MKOFF) ) {
          {
            char buf[MAXSTR];
            if ( isOff(uFlag,x.n)
              && get_offset_expression(cmd.ea,x.n,cmd.ea+x.offb,x.addr,buf,sizeof(buf)) )
            {
              out_symbol('+');
              OutLine(buf);
            }
            else
            {
              int offbit = (cmd.auxpref & aux_off16) ? OOFW_16 : OOFW_8;
              if ( ash.uflag & UAS_TOFF )
                OutValue(x,OOF_ADDR|offbit|OOFS_NEEDSIGN|OOF_SIGNED);
              else
                OutValue(x,OOF_ADDR|offbit|OOFS_NEEDSIGN);
            }
          }
        }
        if ( !isGB() ) out_symbol(')');
        break;

  case o_phrase:

        if ( isZ80() && !isFunny() )
        {
          out_symbol((ash.uflag & UAS_GBASM) ? '[' : '(');
          OutReg(x.phrase);
          out_symbol((ash.uflag & UAS_GBASM) ? ']' : ')');
        } else {
          if ( x.phrase == R_hl ) out_register("m");
          else OutReg(x.phrase);
        }
        break;

  case o_void:

        return 0;

  case o_imm:
        {
          const char *name = NULL;
          bool needbrace = false;
          if ( isZ80() )
          {
            switch ( cmd.itype )
            {
              case I5_rst:
                if ( isFunny() )
                {
                  out_long(x.value/8,(char)getRadix(uFlag,x.n));
                  return 1;
                }
              case Z80_im:
              case Z80_bit:
              case Z80_res:
              case Z80_set:
//                name = z80_find_ioport_bit(x.value);
                break;
              case HD_in0:
              case HD_out0:
                name = z80_find_ioport(x.value);
              case I5_in:
              case I5_out:
              case Z80_outaw:
              case Z80_inaw:
                if ( !isFunny() )
                {
                  out_symbol('(');
                  needbrace = true;
                }
                break;
              default:
                if ( ash.uflag & UAS_MKIMM ) out_symbol('#');
                break;
            }
          }
          if ( name != NULL )
            out_line(name, COLOR_IMPNAME);
          else
            OutValue(x, 0);
          if ( needbrace ) out_symbol(')');
        }
        break;

  case o_mem:
        if ( isZ80() && ! isFunny() )
          out_symbol((ash.uflag & UAS_GBASM) ? '[' : '(');
  case o_near:
        {
          ea_t base;
          if ( x.type == o_mem )
            base = dataSeg_op(x.n);
          else
            base = codeSeg(x.addr,x.n);
          ea_t v = toEA(base,x.addr);
//          const char *ptr;
          if ( v == cmd.ea && ash.a_curip != NULL )
          {
            OutLine(ash.a_curip);
          }
          else if ( !out_name_expr(x, v, x.addr) )
          {
            out_tagon(COLOR_ERROR);
            OutLong(x.addr,16);
            out_tagoff(COLOR_ERROR);
            QueueMark(Q_noName,cmd.ea);
          }
          if ( x.type == o_mem && isZ80() && !isFunny() )
            out_symbol((ash.uflag & UAS_GBASM) ? ']' : ')');
        }
        break;

  default:
        warning("bad optype %x", x.type);
        break;
  }
  return 1;
}

//----------------------------------------------------------------------
static bool isIxyByte(op_t &x)
{
  return x.type == o_reg &&
        (x.reg == R_xl ||
         x.reg == R_xh ||
         x.reg == R_yl ||
         x.reg == R_yh);
}

//----------------------------------------------------------------------
inline bool isIxyOperand(op_t &x)
{
  return isIxyByte(x) || x.type == o_displ;
}

//----------------------------------------------------------------------
void idaapi i5_out(void)
{
  char buf[MAXSTR];

  init_output_buffer(buf, sizeof(buf));

  if (  (ash.uflag & UAS_UNDOC) &&
               (isIxyOperand(cmd.Op1) && isIxyOperand(cmd.Op2))
     || (ash.uflag & UAS_UNDOC) == 0 &&
                (isIxyByte(cmd.Op1)  ||
                 isIxyByte(cmd.Op2)  ||
                 (cmd.itype == I5_adc || cmd.itype == Z80_sbc) &&
                 (cmd.Op1.reg == R_ix || cmd.Op1.reg == R_iy))
     ) {
    OutBadInstruction();
  }
  OutMnem();

  char comma = (char)out_one_operand(0);

  if ( comma && cmd.Op2.showed() && cmd.Op2.type != o_void ) {
    out_symbol(',');
    out_symbol(' ');
  }

  out_one_operand(1);

  if ( isVoid(cmd.ea,uFlag,0) ) OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea,uFlag,1) ) OutImmChar(cmd.Op2);

  term_output_buffer();
  gl_comm = 1;
  MakeLine(buf);
}

//--------------------------------------------------------------------------
void idaapi i5_header(void)
{
  char buf[MAXSTR];
  gen_cmt_line("Processor       : %s [%s]", device[0] ? device : inf.get_proc_name(buf), deviceparams);
  gen_cmt_line("Target assembler: %s",ash.name);
  if ( ash.header != NULL )
    for ( const char **ptr=ash.header; *ptr != NULL; ptr++ ) MakeLine(*ptr,0);
}

//--------------------------------------------------------------------------
void idaapi i5_segstart(ea_t ea)
{
  segment_t *segm = getseg(ea);

  char sname[MAXNAMELEN];
  get_true_segm_name(segm, sname, sizeof(sname));

  if ( ash.uflag & UAS_GBASM )
  {
    printf_line(inf.indent, COLSTR("SECTION \"%s\", %s",SCOLOR_ASMDIR),
                        sname,
                        segtype(ea) == SEG_CODE ? "CODE" : "DATA");
  }
  else if ( ash.uflag & UAS_ZMASM )
  {
    const char *dir = "segment";
    if ( strcmp(sname, ".text") == 0
      || strcmp(sname, ".data") == 0
      || strcmp(sname, ".bss") == 0  )
    {
      dir = sname;
      sname[0] = '\0';
    }
    printf_line(inf.indent, COLSTR("%s %s",SCOLOR_ASMDIR), dir, sname);
  }
  else if ( ash.uflag & UAS_CSEGS )
  {
    gen_cmt_line("segment '%s'", sname);
    printf_line(inf.indent,COLSTR("%cseg",SCOLOR_ASMDIR),segm->align == saAbs ? 'a' : 'c');
  }
  if ( inf.s_org )
  {
    ea_t org = ea - get_segm_base(segm);
    if ( org != 0 )
    {
      char buf[MAX_NUMBUF];
      btoa(buf, sizeof(buf), org);
      printf_line(inf.indent, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
    }
  }
}

//--------------------------------------------------------------------------
void idaapi i5_footer(void)
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
      if ( ash.uflag & UAS_NOENS )
      {
        MakeLine(buf, inf.indent);
        ptr = buf;
        APPEND(ptr, end, ash.cmnt);
      }
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
