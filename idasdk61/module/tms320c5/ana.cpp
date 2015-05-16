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

static uint code;
//----------------------------------------------------------------------
inline ushort GetNextByte(void) {
  return (ushort)get_full_byte(cmd.ea + cmd.size++);
}

//----------------------------------------------------------------------
inline void op_daddr(op_t &o) {         // 16-bit address data
  o.type = o_mem;
  o.addr = GetNextByte();
  o.sib  = 1;
}

//----------------------------------------------------------------------
inline void op_paddr(op_t &o) {         // 16-bit address prog
  o.type = o_near;
  o.addr = GetNextByte();
}

//----------------------------------------------------------------------
inline void op_ioaddr(op_t &o) {        // 16-bit port address
  o.dtyp = dt_word;
  o.type = o_imm;
  o.value = GetNextByte();
  o.sib = 1;
}

//----------------------------------------------------------------------
static int op_iaa(op_t &o) {       // direct or indirect address
  if ( code & 0x80 ) {
    o.type = o_phrase;
    o.phrase = (code & 0x7F);
    if ( (o.phrase & 0x70) == 0x30 ) return 0;
  } else {
    o.type = o_mem;
    o.addr = (getSR(cmd.ea,rDP)<<7) + (code & 0x7F);
    o.sib  = 0;
  }
  return 1;
}

//----------------------------------------------------------------------
static int op_indir(op_t &o) {          // direct or indirect address
                                        // optional
  o.type = o_phrase;
  o.phrase = (code & 0x7F);
  if ( (o.phrase & 0x70) == 0x30 ) return 0;
  if ( (o.phrase & 0x70) == 0 ) o.clr_showed();
  return 1;
}

//----------------------------------------------------------------------
inline int op_maa(op_t &o) {            // memory-mapped register from code
  if ( !op_iaa(o) ) return 0;
  if ( o.type == o_mem ) o.addr = (code & 0x7F);
  return 1;
}

//----------------------------------------------------------------------
inline void op_ar(op_t &o,uint16 ar) {  // aux register
  o.type = o_reg;
  o.reg = rAr0 + ar;
}

//----------------------------------------------------------------------
inline void op_imm(op_t &o) {           // 16-bit immediate
  o.dtyp = dt_word;
  o.type = o_imm;
  o.value = GetNextByte();
  o.sib = 0;
}

//----------------------------------------------------------------------
inline void op_shift(op_t &o,int shift) { // shift
  o.type = o_imm;
  o.value = shift;
  o.sib = 2;
  if ( o.value == 0 ) o.clr_showed();
}

//----------------------------------------------------------------------
inline void op_short(op_t &o) {         // short immediate
  o.dtyp = dt_byte;
  o.type = o_imm;
  o.value = code & 0xFF;
  o.sib = 0;
}

//----------------------------------------------------------------------
inline void op_cbit(op_t &o,int bit) {
  o.type = o_bit;
  o.value = bit;
}

//----------------------------------------------------------------------
static int op_cond(op_t &o)
{
  o.type = o_cond;
  o.Cond = uint16(o.value = (code & 0x3FF));
  int mask = int(o.value>>0) & 0xF;
  int cond = int(o.value>>4) & 0xF;
  if ( ((mask>>2) & 3) == 3 ) { // Z L
    switch( (cond>>2)&3 ) {
      case 0:
      case 1:
        return 0;
    }
  }
  return 1;
}

//----------------------------------------------------------------------
inline void op_bit(op_t &o) {
  o.type = o_imm;
// strange? documentation say this way:  o.value = 15 - ((code >> 8) & 0xF);
// assembler works this way:
  o.value = (code >> 8) & 0xF;
  o.sib = 3;
}

//----------------------------------------------------------------------
//----------------------------------------------------------------------
static int ana_c2(void)
{
  uchar subcode = (code >> 8) & 0xF;
  switch ( code >> 12 ) {
// 0000 SSSS MDDD DDDD          TMS2_add
// 0001 SSSS MDDD DDDD          TMS2_sub
// 0010 SSSS MDDD DDDD          TMS2_lac
    case 0:
      cmd.itype = TMS2_add;
      goto iaa_shift;
    case 1:
      cmd.itype = TMS2_sub;
      goto iaa_shift;
    case 2:
      cmd.itype = TMS2_lac;
iaa_shift:
      if ( !op_iaa(cmd.Op1) ) return 0;
      op_shift(cmd.Op2,subcode);
      break;

// 0011 0RRR MDDD DDDD          TMS2_lar
// 0011 1000 MDDD DDDD          TMS2_mpy
// 0011 1001 MDDD DDDD          TMS2_sqra
// 0011 1010 MDDD DDDD          TMS2_mpya
// 0011 1011 MDDD DDDD          TMS2_mpys
// 0011 1100 MDDD DDDD          TMS2_lt
// 0011 1101 MDDD DDDD          TMS2_lta
// 0011 1110 MDDD DDDD          TMS2_ltp
// 0011 1111 MDDD DDDD          TMS2_ltd
    case 3:
      if ( subcode < 8 ) {
        cmd.itype = TMS2_lar;
        op_ar(cmd.Op1,subcode);
        if ( !op_iaa(cmd.Op2) ) return 0;
      } else {
        static uchar codes[8] = { TMS2_mpy,TMS2_sqra,TMS2_mpya,TMS2_mpys,
                                  TMS2_lt, TMS2_lta, TMS2_ltp, TMS2_ltd  };
        cmd.itype = codes[subcode-8];
        if ( !op_iaa(cmd.Op1) ) return 0;
      }
      break;

// 0100 0000 MDDD DDDD          TMS2_zalh
// 0100 0001 MDDD DDDD          TMS2_zals
// 0100 0010 MDDD DDDD          TMS2_lact
// 0100 0011 MDDD DDDD          TMS2_addc
// 0100 0100 MDDD DDDD          TMS2_subh
// 0100 0101 MDDD DDDD          TMS2_subs
// 0100 0110 MDDD DDDD          TMS2_subt
// 0100 0111 MDDD DDDD          TMS2_subc
// 0100 1000 MDDD DDDD          TMS2_addh
// 0100 1001 MDDD DDDD          TMS2_adds
// 0100 1010 MDDD DDDD          TMS2_addt
// 0100 1011 MDDD DDDD          TMS2_rpt
// 0100 1100 MDDD DDDD          TMS2_xor
// 0100 1101 MDDD DDDD          TMS2_or
// 0100 1110 MDDD DDDD          TMS2_and
// 0100 1111 MDDD DDDD          TMS2_subb
    case 4:
      {
        static ushort codes[16] = { TMS2_zalh,TMS2_zals,TMS2_lact,TMS2_addc,
                                    TMS2_subh,TMS2_subs,TMS2_subt,TMS2_subc,
                                    TMS2_addh,TMS2_adds,TMS2_addt,TMS2_rpt,
                                    TMS2_xor, TMS2_or,  TMS2_and, TMS2_subb };
        cmd.itype = codes[subcode];
        if ( !op_iaa(cmd.Op1) ) return 0;
      }
      break;

// 0101 0000 MDDD DDDD          TMS2_lst
// 0101 0001 MDDD DDDD          TMS2_lst1
// 0101 0010 MDDD DDDD          TMS2_ldp
// 0101 0011 MDDD DDDD          TMS2_lph
// 0101 0100 MDDD DDDD          TMS2_pshd
// 0101 0101 0000 0000          TMS2_nop
// 0101 0101 1000 1RRR          TMS2_larp
// 0101 0101 MDDD DDDD          TMS2_mar
// 0101 0110 MDDD DDDD          TMS2_dmov
// 0101 0111 MDDD DDDD          TMS2_bitt
// 0101 1000 MDDD DDDD          TMS2_tblr
// 0101 1001 MDDD DDDD          TMS2_tblw
// 0101 1010 MDDD DDDD          TMS2_sqrs
// 0101 1011 MDDD DDDD          TMS2_lts
// 0101 1100 MDDD DDDD +1       TMS2_macd
// 0101 1101 MDDD DDDD +1       TMS2_mac
// 0101 1110 1DDD DDDD +1       TMS2_bc
// 0101 1111 1DDD DDDD +1       TMS2_bnc
    case 5:
      {
        static ushort codes[16] = { TMS2_lst, TMS2_lst1,TMS2_ldp, TMS2_lph,
                                    TMS2_pshd,TMS2_mar, TMS2_dmov,TMS2_bitt,
                                    TMS2_tblr,TMS2_tblw,TMS2_sqrs,TMS2_lts,
                                    TMS2_macd,TMS2_mac, TMS2_bc,  TMS2_bnc  };
        cmd.itype = codes[subcode];
        if ( subcode >= 12 ) {
          op_paddr(cmd.Op1);
          if ( subcode >= 14 ) {
            if ( !op_indir(cmd.Op2) ) return 0;
          } else {
            if ( !op_iaa(cmd.Op2) ) return 0;
          }
        } else {
          if ( subcode == 5 ) {
            if ( (code & 0x80) == 0 ) {
              cmd.itype = TMS2_nop;
              cmd.Op1.type = o_void;
              break;
            } else if ( (code & 0xF8) == 0x88 ) {
              cmd.itype = TMS2_larp;
              cmd.Op1.type = o_reg;
              cmd.Op1.reg = rAr0 + (code & 7);
              break;
            }
          }
          if ( !op_iaa(cmd.Op1) ) return 0;
        }
      }
      break;

// 0110 0XXX MDDD DDDD          TMS2_sacl
// 0110 1XXX MDDD DDDD          TMS2_sach
    case 6:
      cmd.itype = (subcode & 8) ? TMS2_sach : TMS2_sacl;
      if ( !op_iaa(cmd.Op1) ) return 0;
      op_shift(cmd.Op2,subcode & 7);
      break;

// 0111 0RRR MDDD DDDD          TMS2_sar
// 0111 1000 MDDD DDDD          TMS2_sst
// 0111 1001 MDDD DDDD          TMS2_sst1
// 0111 1010 MDDD DDDD          TMS2_popd
// 0111 1011 MDDD DDDD          TMS2_zalr
// 0111 1100 MDDD DDDD          TMS2_spl
// 0111 1101 MDDD DDDD          TMS2_sph
// 0111 1110 KKKK KKKK          TMS2_adrk
// 0111 1111 KKKK KKKK          TMS2_sbrk
    case 7:
      if ( subcode < 8 ) {
        cmd.itype = TMS2_sar;
        op_ar(cmd.Op1,subcode);
        if ( !op_iaa(cmd.Op2) ) return 0;
      } else {
        static ushort codes[8] = { TMS2_sst,TMS2_sst1,TMS2_popd,TMS2_zalr,
                                   TMS2_spl,TMS2_sph, TMS2_adrk,TMS2_sbrk  };
        cmd.itype = codes[subcode-8];
        if ( subcode >= 14 ) op_short(cmd.Op1);
        else if ( !op_iaa(cmd.Op1) ) return 0;
      }
      break;

// 1000 AAAA MDDD DDDD          TMS2_in
    case 8:
      cmd.itype = TMS2_in;
      if ( !op_iaa(cmd.Op1) ) return 0;
      cmd.Op2.value = subcode;
      cmd.Op2.type  = o_imm;
      cmd.Op2.sib   = 1;
      break;

// 1001 BBBB MDDD DDDD          TMS2_bit
    case 9:
      cmd.itype = TMS2_bit;
      if ( !op_iaa(cmd.Op1) ) return 0;
      cmd.Op2.value = subcode;
      cmd.Op2.type  = o_imm;
      cmd.Op2.sib   = 0;
      break;

// 101K KKKK KKKK KKKK          TMS2_mpyk
    case 0xA:
    case 0xB:
      cmd.itype = TMS2_mpyk;
      cmd.Op1.value = code & 0x1FFF;
      if ( (cmd.Op1.value & 0x1000) != 0 ) cmd.Op1.value |= ~0x1FFF; // extend sign
      cmd.Op1.type  = o_imm;
      cmd.Op1.sib   = 0;
      break;

// 1100 0RRR KKKK KKKK          TMS2_lark
// 1100 100K KKKK KKKK          TMS2_ldpk
// 1100 1010 0000 0000          TMS2_zac
// 1100 1010 KKKK KKKK          TMS2_lack
// 1100 1011 KKKK KKKK          TMS2_rptk
// 1100 1100 KKKK KKKK          TMS2_addk
// 1100 1101 KKKK KKKK          TMS2_subk
// 1100 1110 0000 0000          TMS2_eint
// 1100 1110 0000 0001          TMS2_dint
// 1100 1110 0000 0010          TMS2_rovm
// 1100 1110 0000 0011          TMS2_sovm
// 1100 1110 0000 0100          TMS2_cnfd
// 1100 1110 0000 0101          TMS2_cnfp
// 1100 1110 0000 0110          TMS2_rsxm
// 1100 1110 0000 0111          TMS2_ssxm
// 1100 1110 0000 10KK          TMS2_spm
// 1100 1110 0000 1100          TMS2_rxf
// 1100 1110 0000 1101          TMS2_sxf
// 1100 1110 0000 111K          TMS2_fort
// 1100 1110 0001 0100          TMS2_pac
// 1100 1110 0001 0101          TMS2_apac
// 1100 1110 0001 0110          TMS2_spac
// 1100 1110 0001 1000          TMS2_sfl
// 1100 1110 0001 1001          TMS2_sfr
// 1100 1110 0001 1011          TMS2_abs
// 1100 1110 0001 1100          TMS2_push
// 1100 1110 0001 1101          TMS2_pop
// 1100 1110 0001 1110          TMS2_trap
// 1100 1110 0001 1111          TMS2_idle
// 1100 1110 0010 0000          TMS2_rtxm
// 1100 1110 0010 0001          TMS2_stxm
// 1100 1110 0010 0011          TMS2_neg
// 1100 1110 0010 0100          TMS2_cala
// 1100 1110 0010 0101          TMS2_bacc
// 1100 1110 0010 0110          TMS2_ret
// 1100 1110 0010 0111          TMS2_cmpl
// 1100 1110 0011 0000          TMS2_rc
// 1100 1110 0011 0001          TMS2_sc
// 1100 1110 0011 0010          TMS2_rtc
// 1100 1110 0011 0011          TMS2_stc
// 1100 1110 0011 0100          TMS2_rol
// 1100 1110 0011 0101          TMS2_ror
// 1100 1110 0011 0110          TMS2_rfsm
// 1100 1110 0011 0111          TMS2_sfsm
// 1100 1110 0011 1000          TMS2_rhm
// 1100 1110 0011 1001          TMS2_shm
// 1100 1110 0011 11KK          TMS2_conf
// 1100 1110 0101 00KK          TMS2_cmpr
// 1100 1110 1AAA 0010          TMS2_norm
// 1100 1111 MDDD DDDD          TMS2_mpyu
    case 0xC:
      switch ( subcode ) {
        default:                // 1100 0RRR KKKK KKKK          TMS2_lark
          cmd.itype = TMS2_lark;
          op_ar(cmd.Op1,subcode);
          op_short(cmd.Op2);
          break;
        case 8:
        case 9:                 // 1100 100K KKKK KKKK          TMS2_ldpk
          cmd.itype = TMS2_ldpk;
          cmd.Op1.dtyp     = dt_word;
          cmd.Op1.value    = code & 0x1FF;
          cmd.Op1.type     = o_imm;
          cmd.Op1.sib      = 0;
          break;
        case 0xA:
          if ( code == 0xCA00 ) {
            cmd.itype = TMS2_zac;
            break;
          }
          cmd.itype = TMS2_lack;
          goto LOAD_SHORT;
        case 0xB:
          cmd.itype = TMS2_rptk;
          op_short(cmd.Op1);
          cmd.Op1.sib = 1;
          break;
        case 0xC:
          cmd.itype = TMS2_addk;
          goto LOAD_SHORT;
        case 0xD:
          cmd.itype = TMS2_subk;
LOAD_SHORT:
          op_short(cmd.Op1);
          break;
        case 0xE:
          switch ( (code>>4) & 0xF ) {
                                //      0000 0000 TMS2_eint
                                //      0000 0001 TMS2_dint
                                //      0000 0010 TMS2_rovm
                                //      0000 0011 TMS2_sovm
                                //      0000 0100 TMS2_cnfd
                                //      0000 0101 TMS2_cnfp
                                //      0000 0110 TMS2_rsxm
                                //      0000 0111 TMS2_ssxm
                                //      0000 10KK TMS2_spm
                                //      0000 1100 TMS2_rxf
                                //      0000 1101 TMS2_sxf
                                //      0000 111K TMS2_fort
            case 0:
              {
                static ushort codes[] = {
                  TMS2_eint, TMS2_dint, TMS2_rovm, TMS2_sovm,
                  TMS2_cnfd, TMS2_cnfp, TMS2_rsxm, TMS2_ssxm,
                  TMS2_spm,  TMS2_spm,  TMS2_spm,  TMS2_spm,
                  TMS2_rxf,  TMS2_sxf,  TMS2_fort, TMS2_fort
                };
                cmd.itype = codes[code & 0xF];
                if ( cmd.itype == TMS2_spm ) {
                  cmd.Op1.value = code & 3;
                  cmd.Op1.type  = o_imm;
                  cmd.Op1.sib   = 0;
                } else if ( cmd.itype == TMS2_fort ) {
                  cmd.Op1.value = code & 1;
                  cmd.Op1.type  = o_imm;
                  cmd.Op1.sib   = 0;
                }
              }
              break;

                                //      0001 0100 TMS2_pac
                                //      0001 0101 TMS2_apac
                                //      0001 0110 TMS2_spac
                                //      0001 1000 TMS2_sfl
                                //      0001 1001 TMS2_sfr
                                //      0001 1011 TMS2_abs
                                //      0001 1100 TMS2_push
                                //      0001 1101 TMS2_pop
                                //      0001 1110 TMS2_trap
                                //      0001 1111 TMS2_idle
            case 1:
              {
                static ushort codes[] = {
                  TMS_null,  TMS_null,  TMS_null,  TMS_null,
                  TMS2_pac,  TMS2_apac, TMS2_spac, TMS_null,
                  TMS2_sfl,  TMS2_sfr,  TMS_null,  TMS2_abs,
                  TMS2_push, TMS2_pop,  TMS2_trap, TMS2_idle
                };
                cmd.itype = codes[code & 0xF];
              }
              break;

                                //      0010 0000 TMS2_rtxm
                                //      0010 0001 TMS2_stxm
                                //      0010 0011 TMS2_neg
                                //      0010 0100 TMS2_cala
                                //      0010 0101 TMS2_bacc
                                //      0010 0110 TMS2_ret
                                //      0010 0111 TMS2_cmpl
            case 2:
              if ( (code & 0xF) < 8 ) {
                static ushort codes[] = {
                  TMS2_rtxm, TMS2_stxm, TMS_null,  TMS2_neg,
                  TMS2_cala, TMS2_bacc, TMS2_ret,  TMS2_cmpl
                };
                cmd.itype = codes[code & 0xF];
              }
              break;

                                //      0011 0000 TMS2_rc
                                //      0011 0001 TMS2_sc
                                //      0011 0010 TMS2_rtc
                                //      0011 0011 TMS2_stc
                                //      0011 0100 TMS2_rol
                                //      0011 0101 TMS2_ror
                                //      0011 0110 TMS2_rfsm
                                //      0011 0111 TMS2_sfsm
                                //      0011 1000 TMS2_rhm
                                //      0011 1001 TMS2_shm
                                //      0011 11KK TMS2_conf
            case 3:
              if ( (code & 0xF) >= 0xC ) {
                cmd.itype = TMS2_conf;
                cmd.Op1.value = code & 3;
                cmd.Op1.type  = o_imm;
                cmd.Op1.sib   = 0;
              } else {
                static ushort codes[] = {
                  TMS2_rc,   TMS2_sc,   TMS2_rtc,  TMS2_stc,
                  TMS2_rol,  TMS2_ror,  TMS2_rfsm, TMS2_sfsm,
                  TMS2_rhm,  TMS2_shm,  TMS_null,  TMS_null,
                };
                cmd.itype = codes[code & 0xF];
              }
              break;

                                //      0101 00KK TMS2_cmpr
            case 5:
              if ( (code & 0xC) == 0 ) {
                cmd.itype = TMS2_cmpr;
                cmd.Op1.value = code & 3;
                cmd.Op1.type  = o_imm;
                cmd.Op1.sib   = 0;
              }
              break;

                                //      1AAA 0010 TMS2_norm
            case 0x8:
            case 0x9:
            case 0xA:
            case 0xB:
            case 0xC:
            case 0xD:
            case 0xE:
            case 0xF:
              cmd.itype = TMS2_norm;
              op_indir(cmd.Op1);
              break;

            default:
              return 0;
          }
          break;
        case 0xF:       // 1100 1111 MDDD DDDD          TMS2_mpyu
          cmd.itype = TMS2_mpyu;
          if ( !op_iaa(cmd.Op1) ) return 0;
          break;
      }
      break;

// 1101 0RRR 0000 0000 +1       TMS2_lrlk
// 1101 SSSS 0000 0001 +1       TMS2_lalk
// 1101 SSSS 0000 0010 +1       TMS2_adlk
// 1101 SSSS 0000 0011 +1       TMS2_sblk
// 1101 SSSS 0000 0100 +1       TMS2_andk
// 1101 SSSS 0000 0101 +1       TMS2_ork
// 1101 SSSS 0000 0110 +1       TMS2_xork
    case 0xD:
      {
        uint opcode = code & 0xFF;
        if ( opcode == 0 ) {
          if ( subcode >= 8 ) return 0;
          cmd.itype = TMS2_lrlk;
          op_ar(cmd.Op1,subcode);
          op_imm(cmd.Op2);
        } else if ( opcode < 7 ) {
          static ushort codes[] = {
                        0,         TMS2_lalk, TMS2_adlk, TMS2_sblk,
                        TMS2_andk, TMS2_ork,  TMS2_xork,            };
          cmd.itype = codes[opcode];
          op_imm(cmd.Op1);
          op_shift(cmd.Op2,subcode);
        } else return 0;
      }
      break;

// 1110 AAAA MDDD DDDD          TMS2_out
    case 0xE:
      cmd.itype = TMS2_out;
      if ( !op_iaa(cmd.Op1) ) return 0;
      cmd.Op2.value = subcode;
      cmd.Op2.type  = o_imm;
      cmd.Op2.sib   = 1;
      break;

// 1111 0000 1DDD DDDD +1       TMS2_bv
// 1111 0001 1DDD DDDD +1       TMS2_bgz
// 1111 0010 1DDD DDDD +1       TMS2_blez
// 1111 0011 1DDD DDDD +1       TMS2_blz
// 1111 0100 1DDD DDDD +1       TMS2_bgez
// 1111 0101 1DDD DDDD +1       TMS2_bnz
// 1111 0110 1DDD DDDD +1       TMS2_bz
// 1111 0111 1DDD DDDD +1       TMS2_bnv
// 1111 1000 1DDD DDDD +1       TMS2_bbz
// 1111 1001 1DDD DDDD +1       TMS2_bbnz
// 1111 1010 1DDD DDDD +1       TMS2_bioz
// 1111 1011 1DDD DDDD +1       TMS2_banz
// 1111 1100 MDDD DDDD +1       TMS2_blkp
// 1111 1101 MDDD DDDD +1       TMS2_blkd
// 1111 1110 1DDD DDDD +1       TMS2_call
// 1111 1111 1DDD DDDD +1       TMS2_b
    case 0xF:
      {
        static ushort codes[16] = {
                        TMS2_bv,  TMS2_bgz, TMS2_blez,TMS2_blz,
                        TMS2_bgez,TMS2_bnz, TMS2_bz,  TMS2_bnv,
                        TMS2_bbz, TMS2_bbnz,TMS2_bioz,TMS2_banz,
                        TMS2_blkp,TMS2_blkd,TMS2_call,TMS2_b    };
        cmd.itype = codes[subcode];
        op_paddr(cmd.Op1);
        switch ( cmd.itype ) {
          case TMS2_blkd:
            cmd.Op1.type = o_mem;
            cmd.Op1.sib  = 1;
          case TMS2_blkp:
            if ( !op_iaa(cmd.Op2) ) return 0;
            break;
          default:
            if ( !op_indir(cmd.Op2) ) return 0;
            break;
        }
      }
      break;
   }
   return 1;
}

//----------------------------------------------------------------------
//----------------------------------------------------------------------
int idaapi ana(void) {

  cmd.Op1.dtyp = dt_byte;
  cmd.Op2.dtyp = dt_byte;
  cmd.itype = TMS_null;
  cmd.auxpref  = 0;

  code = GetNextByte();
  uchar subcode = (code >> 8) & 0xF;
  uint nibble;

  if ( isC2() ) { if ( !ana_c2() ) return 0; }
  else switch ( code >> 12 ) {
    case 0:
      if ( subcode < 8 ) {
        cmd.itype = TMS_lar;
        op_ar(cmd.Op1,subcode);
        if ( !op_iaa(cmd.Op2) ) return 0;
      } else {
        {
          static uchar codes[8] = { TMS_lamm,TMS_smmr,TMS_subc,TMS_rpt,
                                    TMS_out, TMS_ldp, TMS_lst, TMS_lst };
          cmd.itype = codes[subcode-8];
        }
        if ( subcode == 0xC ) op_ioaddr(cmd.Op2);
case08_common:
        if (
            !((subcode == 0x8 ||
               subcode == 0x9 )  ? op_maa : op_iaa)(cmd.Op1) ) return 0;
        if ( subcode == 0x9 ) { op_daddr(cmd.Op2); }
        if ( subcode >= 0xE ) {
          if ( cmd.itype == TMS_sst ) op_maa(cmd.Op1);
          cmd.Op2 = cmd.Op1;
          cmd.Op2.n = 1;
          cmd.Op1.type = o_imm;
          cmd.Op1.value = subcode & 1;
          cmd.Op1.sib = 0;
        }
      }
      break;
    case 8:
      if ( subcode < 8 ) {
        cmd.itype = TMS_sar;
        op_ar(cmd.Op1,subcode);
        if ( !op_iaa(cmd.Op2) ) return 0;
      } else {
        static uchar codes[8] = { TMS_samm,TMS_lmmr,TMS_popd,TMS_mar,
                                  TMS_spl, TMS_sph, TMS_sst, TMS_sst };
        cmd.itype = codes[subcode-8];
        if ( subcode == 0xB && (code & 0xFF) == 0 ) {
          cmd.itype = TMS_nop;
          cmd.Op1.type = o_void;
          break;
        }
        goto case08_common;
      }
      break;
    case 1:
      cmd.itype = TMS_lacc;
      goto iaa_shift;
    case 2:
      cmd.itype = TMS_add;
      goto iaa_shift;
    case 3:
      cmd.itype = TMS_sub;
iaa_shift:
      if ( !op_iaa(cmd.Op1) ) return 0;
      op_shift(cmd.Op2,subcode);
      break;
    case 4:
      cmd.itype = TMS_bit;
      if ( !op_iaa(cmd.Op1) ) return 0;
      op_bit(cmd.Op2);
      break;
    case 5:
      {
        static uchar codes[16] = {
                        TMS_mpya,TMS_mpys,TMS_sqra,TMS_sqrs,
                        TMS_mpy, TMS_mpyu,TMS_null,TMS_bldp,
                        TMS_xpl, TMS_opl, TMS_apl, TMS_cpl,
                        TMS_xpl2,TMS_opl2,TMS_apl2,TMS_cpl2
        };
        cmd.itype = codes[subcode];
        if ( !op_iaa(cmd.Op1) ) return 0;
        op_t *o;
        if ( subcode >= 0xC ) {
          op_imm(cmd.Op1);
          o = &cmd.Op2;
        } else {
          o = &cmd.Op1;
        }
        if ( !op_iaa(*o) ) return 0;
      }
      break;
     case 6:
      {
        static uchar codes[16] = {
                        TMS_addc,TMS_add, TMS_adds,TMS_addt,
                        TMS_subb,TMS_sub, TMS_subs,TMS_subt,
                        TMS_zalr,TMS_lacl,TMS_lacc,TMS_lact,
                        TMS_xor, TMS_or,  TMS_and, TMS_bitt
        };
        cmd.itype = codes[subcode];
        if ( !op_iaa(cmd.Op1) ) return 0;
        if ( cmd.itype == TMS_lacc ||
             cmd.itype == TMS_add  ||
             cmd.itype == TMS_sub     ) op_shift(cmd.Op2,16);
      }
      break;
    case 7:
      {
        static uchar codes[16] = {
                        TMS_lta, TMS_ltp, TMS_ltd,  TMS_lt,
                        TMS_lts, TMS_lph, TMS_pshd, TMS_dmov,
                        TMS_adrk,TMS_b,   TMS_call, TMS_banz,
                        TMS_sbrk,TMS_bd,  TMS_calld,TMS_banzd
        };
        cmd.itype = codes[subcode];
        if ( subcode < 8 ) {
          if ( !op_iaa(cmd.Op1) ) return 0;
        } else {
          if ( subcode != 8 && subcode != 0xC ) {
            op_paddr(cmd.Op1);
            if ( !op_iaa(cmd.Op2) ||
                 cmd.Op2.type != o_phrase ) cmd.itype = TMS_null;
          } else {
            op_short(cmd.Op1);
          }
        }
      }
      break;
    case 9:
      cmd.itype = (subcode & 8) ? TMS_sach : TMS_sacl;
      if ( !op_iaa(cmd.Op1) ) return 0;
      op_shift(cmd.Op2,subcode&7);
      break;
    case 0xA:
      {
        static uchar codes[16] = {
                        TMS_norm,TMS_null,TMS_mac, TMS_macd,
                        TMS_blpd,TMS_blpd,TMS_tblr,TMS_tblw,
                        TMS_bldd,TMS_bldd,TMS_mads,TMS_madd,
                        TMS_bldd,TMS_bldd,TMS_splk,TMS_in
        };
        cmd.itype = codes[subcode];
        switch ( subcode ) {
          case 0:
            if ( !op_iaa(cmd.Op1) ) return 0;
            if ( (code & 0x80) == 0 ) cmd.itype = TMS_null;
            break;
          case 4:       // blpd bmar,?
          case 0xC:     // bldd bmar,?
            cmd.Op1.type = o_reg;
            cmd.Op1.reg = rBMAR;
            if ( !op_iaa(cmd.Op2) ) return 0;
            break;
          case 0xD:     // bldd ?,bmar
            if ( !op_iaa(cmd.Op1) ) return 0;
            cmd.Op2.type = o_reg;
            cmd.Op2.reg = rBMAR;
            break;
          case 2:               // mac
          case 3:               // macd
          case 5:               // blpd
            op_paddr(cmd.Op1);
            if ( !op_iaa(cmd.Op2) ) return 0;
            break;
          case 8:
            op_daddr(cmd.Op1);
            if ( !op_iaa(cmd.Op2) ) return 0;
            break;
          case 9:
            if ( !op_iaa(cmd.Op1) ) return 0;
            op_daddr(cmd.Op2);
            break;
          case 0xE:
            op_imm(cmd.Op1);
            if ( !op_iaa(cmd.Op2) ) return 0;
            break;
          case 0xF:
            if ( !op_iaa(cmd.Op1) ) return 0;
            op_ioaddr(cmd.Op2);
            break;
          default:
            if ( !op_iaa(cmd.Op1) ) return 0;
            break;
        }
      }
      break;

    case 0xB:
      switch ( subcode ) {
        case 0: case 1: case 2: case 3:
        case 4: case 5: case 6: case 7:
          cmd.itype = TMS_lar;
          op_ar(cmd.Op1,subcode);
          op_short(cmd.Op2);
          break;
        case 8: case 9: case 0xA: case 0xB:
        case 0xC:
          {
            static uchar codes[] = { TMS_add, TMS_lacl, TMS_sub, TMS_rpt,
                                     TMS_ldp };
            cmd.itype = codes[subcode-8];
            op_short(cmd.Op1);
          }
          break;
        case 0xD:
          cmd.itype = TMS_ldp;
          op_short(cmd.Op1);
          cmd.Op1.value |= 0x100;
          break;
        case 0xE:
          nibble = (code & 0xF);
          switch ( ( code >> 4) & 0xF ) {
            case 0: case 1: case 2: case 3:
              {
                static uchar codes[] = {
                                         TMS_abs, TMS_cmpl, TMS_neg, TMS_pac,
                                         TMS_apac,TMS_spac, TMS_null,TMS_null,
                                         TMS_null,TMS_sfl,  TMS_sfr, TMS_null,
                                         TMS_rol, TMS_ror,  TMS_null,TMS_null,

                                         TMS_addb,TMS_adcb, TMS_andb,TMS_orb,
                                         TMS_rolb,TMS_rorb, TMS_sflb,TMS_sfrb,
                                         TMS_sbb, TMS_sbbb, TMS_xorb,TMS_crgt,
                                         TMS_crlt,TMS_exar, TMS_sacb,TMS_lacb,

                                         TMS_bacc,TMS_baccd,TMS_idle,TMS_idle2,
                                         TMS_null,TMS_null, TMS_null,TMS_null,
                                         TMS_null,TMS_null, TMS_null,TMS_null,
                                         TMS_null,TMS_null, TMS_null,TMS_null,

                                         TMS_cala,TMS_null, TMS_pop, TMS_null,
                                         TMS_null,TMS_null, TMS_null,TMS_null,
                                         TMS_reti,TMS_null, TMS_rete,TMS_null,
                                         TMS_push,TMS_calad,TMS_null,TMS_null
                                       };
                cmd.itype = codes[code & 0x3F];
              }
              break;
            case 4:
              cmd.itype = (code & 1) ? TMS_setc : TMS_clrc;
              op_cbit(cmd.Op1,(code>>1)&7);
              break;
            case 5:
              {
                static uchar codes[] = {
                                         TMS_null, TMS_trap, TMS_nmi,  TMS_null,
                                         TMS_null, TMS_null, TMS_null, TMS_null,
                                         TMS_zpr,  TMS_zap,  TMS_sath, TMS_satl,
                                         TMS_null, TMS_null, TMS_null, TMS_null
                                       };
                cmd.itype = codes[nibble];
              }
              break;
            case 6:
            case 7:
              cmd.itype = TMS_intr;
              cmd.Op1.type = o_imm;
              cmd.Op1.value = (code & 0x1F);
              cmd.Op1.sib = 1;
              break;
            case 8:
              if ( nibble < 4 ) {
                static uchar codes[] = { TMS_mpy, TMS_and, TMS_or, TMS_xor };
                cmd.itype = codes[nibble];
                op_imm(cmd.Op1);
                if ( nibble != 0 ) op_shift(cmd.Op2,16);
              }
              break;
            case 9:
              if ( nibble == 0 ) cmd.itype = TMS_estop;
              break;
            case 0xC:
              switch ( nibble ) {
                case 4:
                  cmd.itype = TMS_rpt;
                  op_imm(cmd.Op1);
                  break;
                case 5:
                  cmd.itype = TMS_rptz;
                  op_imm(cmd.Op1);
                  break;
                case 6:
                  cmd.itype = TMS_rptb;
                  op_paddr(cmd.Op1);
                  break;
              }
              break;
          }
          break;
        case 0xF:
          nibble = (code & 0xF);
          switch ( (code>>4) & 0xF ) {
            case 0:
              if ( code & 8 ) {
                cmd.itype = TMS_lar;
                op_ar(cmd.Op1,code & 7);
                op_imm(cmd.Op2);
              } else {
                cmd.itype = TMS_spm;
                op_short(cmd.Op1);
                cmd.Op1.sib = 1;
              }
              break;
            case 4:
              if ( (nibble & 0xC) == 4 ) {
                cmd.itype = TMS_cmpr;
                cmd.Op1.type = o_imm;
                cmd.Op1.value = nibble & 3;
                cmd.Op1.sib = 1;
              }
              break;
            case 0xE:
              cmd.itype = TMS_bsar;
              op_shift(cmd.Op1,nibble+1);
              break;
            case 8:
            case 9:
            case 0xA:
            case 0xB:
            case 0xC:
            case 0xD:
              {
                static uchar codes[] = { TMS_lacc,TMS_add,TMS_sub,TMS_and,
                                         TMS_or,  TMS_xor
                                       };
                cmd.itype = codes[(code>>4) & 0x7];
                op_imm(cmd.Op1);
                op_shift(cmd.Op2,nibble);
              }
              break;
          }
          break;
      }
      break;
    case 0xC:
    case 0xD:
      cmd.itype = TMS_mpy;
      cmd.Op1.dtyp = dt_word;
      cmd.Op1.type = o_imm;
      cmd.Op1.value = (code & 0x1FFF);
      if ( (cmd.Op1.value & 0x1000) != 0 ) cmd.Op1.value |= ~0x1FFF; // extend sign
      cmd.Op1.sib = 0;
      break;
    case 0xE:
    case 0xF:
      switch ( subcode>>2 ) {
        case 0:
          cmd.itype = (code & 0x1000) ? TMS_bcndd : TMS_bcnd;
          op_paddr(cmd.Op1);
          if ( !op_cond(cmd.Op2) ) return 0;
          break;
        case 1:
          cmd.itype = TMS_xc;
          cmd.Op1.type = o_imm;
          cmd.Op1.value = (code & 0x1000) ? 2 : 1;
          cmd.Op1.sib = 1;
          if ( !op_cond(cmd.Op2) ) return 0;
          break;
        case 2:
          cmd.itype = (code & 0x1000) ? TMS_ccd : TMS_cc;
          op_paddr(cmd.Op1);
          if ( !op_cond(cmd.Op2) ) return 0;
          break;
        case 3:
          if ( (code & 0xEFFF) == 0xEF00 )
            cmd.itype = (code & 0x1000) ? TMS_retd : TMS_ret;
          else {
            cmd.itype = (code & 0x1000) ? TMS_retcd : TMS_retc;
            if ( !op_cond(cmd.Op1) ) return 0;
          }
          break;
      }
      break;
  }
  if ( cmd.itype == TMS_null ) return 0;
  return cmd.size;
}
