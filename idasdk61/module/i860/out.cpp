/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "i860.hpp"

//----------------------------------------------------------------------
inline void OutReg(int rgnum)
{
  out_register(ph.regNames[rgnum]);
}

//----------------------------------------------------------------------
bool idaapi i860_outop(op_t &x)
{
  switch ( x.type )
  {
    case o_reg:
      OutReg(x.reg);
      break;
    case o_displ:
      OutValue(x,OOF_ADDR|OOFW_32);
      goto common;
    case o_phrase:
      OutReg(int(x.addr));
common:
      {
        int s2 = char(x.reg);
        if ( s2 != 0 ) {
          out_symbol('(');
          OutReg(s2 < 0 ? -s2 : s2);
          out_symbol(')');
          if ( char(x.reg) < 0 ) {
            out_symbol('+');
            out_symbol('+');
          }
        }
      }
      break;
    case o_imm:
      OutValue(x,OOF_SIGNED|OOFW_32);
      break;
    case o_mem:
    case o_near:
      if ( !out_name_expr(x, x.addr, x.addr) )
      {
        OutValue(x,OOF_ADDR|OOF_NUMBER|OOFS_NOSIGN|OOFW_32);
        QueueMark(Q_noName,cmd.ea);
      }
      break;
    case o_void:
      return 0;
    default:
      warning("out: %a: bad optype %d", cmd.ea, x.type);
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
void idaapi i860_out(void)
{
  char buf[MAXSTR];
  init_output_buffer(buf, sizeof(buf));

  {
    out_tagon(COLOR_INSN);
    const char *cname = cmd.get_canon_mnem();
    int i = 16 - (inf.indent & 7);
    if ( cmd.auxpref & Dbit )
    {
      OutChar('d');
      OutChar('.');
      i -= 2;
    }
    while ( *cname != 0 )
    {
      OutChar(*cname++);
      i--;
    }
    switch ( cmd.itype )
    {
      case I860_fadd:
      case I860_pfadd:
      case I860_famov:
      case I860_pfamov:
      case I860_fiadd:
      case I860_pfiadd:
      case I860_fisub:
      case I860_pfisub:
      case I860_fix:
      case I860_pfix:
      case I860_fmul:
      case I860_pfmul:
      case I860_frcp:
      case I860_frsqr:
      case I860_fsub:
      case I860_pfsub:
      case I860_ftrunc:
      case I860_pftrunc:
      case I860_pfeq:
      case I860_pfgt:
      case I860_pfle:
      case I860_r2p1:
      case I860_r2pt:
      case I860_r2ap1:
      case I860_r2apt:
      case I860_i2p1:
      case I860_i2pt:
      case I860_i2ap1:
      case I860_i2apt:
      case I860_rat1p2:
      case I860_m12apm:
      case I860_ra1p2:
      case I860_m12ttpa:
      case I860_iat1p2:
      case I860_m12tpm:
      case I860_ia1p2:
      case I860_m12tpa:
      case I860_r2s1:
      case I860_r2st:
      case I860_r2as1:
      case I860_r2ast:
      case I860_i2s1:
      case I860_i2st:
      case I860_i2as1:
      case I860_i2ast:
      case I860_rat1s2:
      case I860_m12asm:
      case I860_ra1s2:
      case I860_m12ttsa:
      case I860_iat1s2:
      case I860_m12tsm:
      case I860_ia1s2:
      case I860_m12tsa:
      case I860_mr2p1:
      case I860_mr2pt:
      case I860_mr2mp1:
      case I860_mr2mpt:
      case I860_mi2p1:
      case I860_mi2pt:
      case I860_mi2mp1:
      case I860_mi2mpt:
      case I860_mrmt1p2:
      case I860_mm12mpm:
      case I860_mrm1p2:
      case I860_mm12ttpm:
      case I860_mimt1p2:
      case I860_mm12tpm:
      case I860_mim1p2:
      case I860_mr2s1:
      case I860_mr2st:
      case I860_mr2ms1:
      case I860_mr2mst:
      case I860_mi2s1:
      case I860_mi2st:
      case I860_mi2ms1:
      case I860_mi2mst:
      case I860_mrmt1s2:
      case I860_mm12msm:
      case I860_mrm1s2:
      case I860_mm12ttsm:
      case I860_mimt1s2:
      case I860_mm12tsm:
      case I860_mim1s2:
        OutChar('.');
        OutChar( (cmd.auxpref & Sbit) ? 'd' : 's');
        OutChar( (cmd.auxpref & Rbit) ? 'd' : 's');
        i -= 3;
        break;
      case I860_fld:
      case I860_fst:
      case I860_ld:
      case I860_ldint:
      case I860_ldio:
      case I860_pfld:
      case I860_scyc:
      case I860_st:
      case I860_stio:
        OutChar('.');
        switch ( cmd.Op1.dtyp )
        {
          case dt_byte:         OutChar('b');   break;
          case dt_word:         OutChar('s');   break;
          case dt_dword:        OutChar('l');   break;
          case dt_qword:        OutChar('d');   break;
          case dt_byte16:       OutChar('q');   break;
        }
        i -= 2;
        break;
    }
    out_tagoff(COLOR_INSN);
    do
    {
      OutChar(' ');
      i--;
    } while ( i > 0 );
  }

  char comma = (char)out_one_operand(0);

  if ( comma && cmd.Op2.showed() && cmd.Op2.type != o_void )
  {
    out_symbol(',');
    OutChar(' ');
  }

  out_one_operand(1);

  if ( comma && cmd.Op3.showed() && cmd.Op3.type != o_void )
  {
    out_symbol(',');
    OutChar(' ');
  }

  out_one_operand(2);

  if ( isVoid(cmd.ea,uFlag,0) ) OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea,uFlag,1) )
  {
    OutImmChar(cmd.Op2);
    OutImmChar(cmd.Op3);
  }

  term_output_buffer();

  gl_comm = 1;
  MakeLine(buf);
}

//--------------------------------------------------------------------------
void idaapi i860_header(void)
{
  gen_cmt_line("Processor:        %s",inf.procName);
}

//--------------------------------------------------------------------------
void idaapi i860_segstart(ea_t ea)
{
  segment_t *Sarea = getseg(ea);
  char sname[MAXNAMELEN];
  get_true_segm_name(Sarea, sname, sizeof(sname));
  printf_line(inf.indent, COLSTR(".text %s %s",SCOLOR_ASMDIR), ash.cmnt, sname);

  const char *p = ".byte";
  switch ( Sarea->align )
  {
    case saRelByte:   p = ".byte";    break;
    case saRelWord:   p = ".word";    break;
    case saRelPara:   p = ".float";   break;
  }
  printf_line(inf.indent, COLSTR(".align %s", SCOLOR_ASMDIR), p);

  if ( inf.s_org )
  {
    ea_t org = ea - get_segm_base(Sarea);
    if ( org != 0 )
    {
      char buf[MAX_NUMBUF];
      btoa(buf, sizeof(buf), org);
      printf_line(inf.indent, COLSTR("%s%s %s",SCOLOR_AUTOCMT), ash.cmnt,
                              ash.origin, buf);
    }
  }
}

//--------------------------------------------------------------------------
void idaapi i860_footer(void)
{
  char buf[MAXSTR];
  if ( ash.end != NULL )
  {
    MakeNull();
    char *ptr = buf;
    char *end = buf + sizeof(buf);
    APPEND(ptr, end, ash.end);
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
