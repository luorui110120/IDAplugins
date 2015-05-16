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
extern netnode ovrtrans;

//----------------------------------------------------------------------
static void loadoper(op_t *Op, uint16 nibble) {

  ushort base;

  switch ( nibble ) {
    case 027:
      Op->type = o_imm;
      Op->ill_imm = isHead(get_flags_novalue(cmd.ea)) ?
                    !isTail(get_flags_novalue(cmd.ea+cmd.size)) :
                    isHead(get_flags_novalue(cmd.ea+cmd.size));
      Op->offb = (uchar)cmd.size;
      Op->value = ua_next_word();
      break;
   case 037:
   case 077:
   case 067:
      Op->type = o_mem;
      Op->offb = (uchar)cmd.size;
      base = ua_next_word();
      if ( (Op->phrase = nibble) != 037) base += (short)(cmd.ip + cmd.size );
      Op->addr16 = base;
      break;
   default:
      if ( (nibble & 070) == 0 ) {
        Op->type = o_reg;
        Op->reg = nibble;
      } else  {
        Op->phrase = nibble;
        if ( nibble < 060 ) Op->type = o_phrase;
        else {
          Op->type = o_displ;
          Op->offb = (uchar)cmd.size;
          Op->addr16 = ua_next_word();
        }
      }
      break;
  }
}
//----------------------------------------------------------------------
static void jmpoper(op_t *Op, uint16 nibble)
{
  loadoper(Op, nibble);
  if ( Op->type == o_mem && Op->phrase != 077 ) Op->type = o_near;
  if(Op->type == o_near &&
     Op->addr16 >= m.ovrcallbeg && Op->addr16 <= m.ovrcallend) {
    uint32 trans = (uint32)ovrtrans.altval(Op->addr16);
// msg("addr=%o, trans=%lo\n", Op->addr16, trans);
    if ( trans != 0 ) {
      segment_t *S = getseg(trans);
      if ( S ) {
        Op->type = o_far;
        Op->segval = (uint16)S->sel;
        Op->addr16 = (ushort)(trans - toEA(Op->segval,0));
      }
    }
  }
}
//----------------------------------------------------------------------
int idaapi ana(void) {

  static const char twoop[5] = {pdp_mov, pdp_cmp, pdp_bit, pdp_bic, pdp_bis};
  static const char onecmd[12] = { pdp_clr, pdp_com, pdp_inc, pdp_dec,
                 pdp_neg, pdp_adc, pdp_sbc, pdp_tst, pdp_ror, pdp_rol,
                 pdp_asr, pdp_asl};
  static const char cc2com[8] = {pdp_bpl, pdp_bmi, pdp_bhi, pdp_blos,
                  pdp_bvc, pdp_bvs, pdp_bcc, pdp_bcs};

  if ( cmd.ip & 1) return(0 );

  cmd.Op1.dtyp = cmd.Op2.dtyp = dt_word;
//  cmd.bytecmd = 0;

  uint code = ua_next_word();

  uchar nibble0 = (code & 077);
  uchar nibble1 = (code >> 6 ) & 077;
  uchar nibble2 = (code >> 12) & 017;
  uchar nib1swt = nibble1 >> 3;

  switch ( nibble2 ) {
    case 017:
      if ( nibble1 == 0 ) {
        switch ( nibble0 ) {
          case   0: cmd.itype = pdp_cfcc; break;
          case   1: cmd.itype = pdp_setf; break;
          case   2: cmd.itype = pdp_seti; break;
          case 011: cmd.itype = pdp_setd; break;
          case 012: cmd.itype = pdp_setl; break;
          default:  return(0);
        }
        break;
      }
      loadoper(&cmd.Op1, nibble0);
      if ( nib1swt != 0 ) {
        static const char fpcom2[14] = { pdp_muld, pdp_modd, pdp_addd,
                pdp_ldd, pdp_subd, pdp_cmpd, pdp_std, pdp_divd, pdp_stexp,
                pdp_stcdi, pdp_stcdf, pdp_ldexp, pdp_ldcif, pdp_ldcfd};
        cmd.Op2.type = o_fpreg;
        cmd.Op2.reg = (nibble1 & 3);
        cmd.Op2.dtyp = dt_double;
        cmd.itype = fpcom2[(nibble1 >> 2) - 2];
        if ( cmd.itype != pdp_ldexp && cmd.itype != pdp_stexp ) {
          if ( cmd.Op1.type == o_reg ) cmd.Op1.type = o_fpreg;
          if ( cmd.itype != pdp_stcdi && cmd.itype != pdp_ldcif )
                                    cmd.Op1.dtyp = dt_double;
        }
        if(cmd.itype == pdp_std || cmd.itype == pdp_stexp ||
           cmd.itype == pdp_stcdi || cmd.itype == pdp_stcdf) {
            op_t temp;
            temp = cmd.Op2;
            cmd.Op2 = cmd.Op1;
            cmd.Op1 = temp;
            cmd.Op1.n = 0;
            cmd.Op2.n = 1;
        }
      } else {
        static const char fpcom1[7] = {
          pdp_ldfps, pdp_stfps, pdp_stst, pdp_clrd,
          pdp_tstd, pdp_absd, pdp_negd};
        if ( nibble1 >= 4 ) {
          cmd.Op1.dtyp = cmd.Op2.dtyp = dt_double;
          if ( cmd.Op1.type == o_reg ) cmd.Op1.type = o_fpreg;
        }
        cmd.itype = fpcom1[nibble1 - 1];
      }
      break;

    case 7:
      switch ( nib1swt ) {
        case 6:           // CIS
            return(0);
        case 5:          // FIS
          {
            static const char ficom[4] = {pdp_fadd, pdp_fsub, pdp_fmul, pdp_fdiv};
            if ( nibble1 != 050 || nibble0 >= 040) return(0 );
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = nibble0 & 7;
            cmd.itype = ficom[nibble0 >> 3];
            break;
          }
        case 7:         // SOB
            cmd.itype = pdp_sob;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = nibble1 & 7;
            cmd.Op2.type = o_near;
            cmd.Op2.phrase = 0;
            cmd.Op2.addr16 = (ushort)(cmd.ip + 2 - (2*nibble0));
            break;
        default:
       {
         static const char eiscom[5]={pdp_mul, pdp_div, pdp_ash, pdp_ashc, pdp_xor};
            cmd.Op2.type = o_reg;
            cmd.Op2.reg = nibble1 & 7;
            loadoper(&cmd.Op1, nibble0);
            cmd.itype = eiscom[nib1swt];
            break;
       }
      }
      break;

    case 016:
      cmd.itype = pdp_sub;
      goto twoopcmd;
    case   6:
      cmd.itype = pdp_add;
      goto twoopcmd;
    default:                      //Normal 2 op
      cmd.itype = twoop[(nibble2 & 7) - 1];
      cmd.bytecmd = ((nibble2 & 010) != 0);
twoopcmd:
      loadoper(&cmd.Op1, nibble1);
      loadoper(&cmd.Op2, nibble0);
      break;

    case 010:
      if ( nibble1 >= 070) return(0 );
      if ( nibble1 >= 064 ) {
         static const char mt1cmd[4] = {pdp_mtps, pdp_mfpd, pdp_mtpd, pdp_mfps};
         cmd.itype = mt1cmd[nibble1 - 064];
         loadoper(&cmd.Op1, nibble0);
         break;
      }
      if ( nibble1 >= 050 ) {
         cmd.bytecmd = 1;
oneoper:
         loadoper(&cmd.Op1, nibble0);
         cmd.itype = onecmd[nibble1 - 050];
         break;
      }
      if ( nibble1 >= 040 ) {
        cmd.Op1.type = o_number;             // EMT/TRAP
        cmd.Op1.value = code & 0377;
        cmd.itype = (nibble1 >= 044) ? pdp_trap : pdp_emt;
        break;
      }
      cmd.itype = cc2com[nibble1 >> 2];
condoper:
      cmd.Op1.type = o_near;
      cmd.Op1.phrase = 0;
      cmd.Op1.addr16 = (ushort)(cmd.ip + cmd.size + (2*(short)((char)code)));
      break;

    case 0:
       if ( nibble1 >= 070) return(0 );
       if ( nibble1 > 064 ) {
         static const char mt2cmd[3] = {pdp_mfpi, pdp_mtpi, pdp_sxt};
         cmd.itype = mt2cmd[nibble1 - 065];
         loadoper(&cmd.Op1, nibble0);
         break;
       }
       if ( nibble1 == 064 ) {
         cmd.itype = pdp_mark;
         cmd.Op1.type = o_number;
         cmd.Op1.value = nibble0;
         break;
       }
       if ( nibble1 >= 050 ) goto oneoper;
       if ( nibble1 >= 040 ) {
          if ( (nibble1 & 7) == 7 ) {
            cmd.itype = pdp_call;
            jmpoper(&cmd.Op1, nibble0);
          } else {
            cmd.itype = pdp_jsr;
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = nibble1 & 7;
            jmpoper(&cmd.Op2, nibble0);
          }
          break;
       }
       switch ( nibble1 ) {
          case 3:
              cmd.itype = pdp_swab;
              loadoper(&cmd.Op1, nibble0);
              break;
          case 1:
              cmd.itype = pdp_jmp;
              jmpoper(&cmd.Op1, nibble0);
              break;
          case 2:
              if ( nibble0 == 7 ) {
                cmd.itype = pdp_return;
                break;
              }
              if ( nibble0 < 7 ) {
                 cmd.itype = pdp_rts;
                 cmd.Op1.type = o_reg;
                 cmd.Op1.reg = nibble0;
                 break;
              }
              if ( nibble0 < 030) return(0 );
              if ( nibble0 < 040 ) {
                cmd.itype = pdp_spl;
                cmd.Op1.value = nibble0 & 7;
                cmd.Op1.type = o_number;
                break;
              }
              switch ( nibble0 & 037 ) {
                 case 000: cmd.itype = pdp_nop; break;
                 case 001: cmd.itype = pdp_clc; break;
                 case 002: cmd.itype = pdp_clv; break;
                 case 004: cmd.itype = pdp_clz; break;
                 case 010: cmd.itype = pdp_cln; break;
                 case 017: cmd.itype = pdp_ccc; break;
                 case 021: cmd.itype = pdp_sec; break;
                 case 022: cmd.itype = pdp_sev; break;
                 case 024: cmd.itype = pdp_sez; break;
                 case 030: cmd.itype = pdp_sen; break;
                 case 037: cmd.itype = pdp_scc; break;
                 default:
                    cmd.itype = pdp_compcc;
                    cmd.Op1.phrase = nibble0 & 037;
                    break;
              }
              break;
          case 0:
           {
              static const char misc0[16] ={pdp_halt, pdp_wait, pdp_rti,  pdp_bpt,
                   pdp_iot, pdp_reset, pdp_rtt, pdp_mfpt };
              if ( nibble0 > 7) return(0 );
              cmd.itype = misc0[nibble0];
              break;
           }
          default:          // >=4
           {
             static const char cc2com[7] = {pdp_br, pdp_bne, pdp_beq, pdp_bge,
                            pdp_blt, pdp_bgt, pdp_ble};

             cmd.itype = cc2com[(nibble1 >> 2) - 1];
             goto condoper;
           }
       }
       break;
  }

  if ( cmd.bytecmd ) {
    if ( (cmd.Op1.type == o_mem && cmd.Op1.phrase != 077 ) ||
       (cmd.Op1.type == o_displ && (cmd.Op1.phrase & 070) == 060))
                cmd.Op1.dtyp = dt_byte;
    if ( (cmd.Op2.type == o_mem && cmd.Op2.phrase != 077 ) ||
       (cmd.Op2.type == o_displ && (cmd.Op2.phrase & 070) == 060))
                cmd.Op2.dtyp = dt_byte;
  }

  if ( cmd.Op1.type == o_imm && cmd.Op1.ill_imm ) cmd.size -= 2;
  if ( cmd.Op2.type == o_imm && cmd.Op2.ill_imm ) cmd.size -= 2;

  return int(cmd.size);
}
