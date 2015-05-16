/*
 *      Rockwell C39 processor module for IDA Pro.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "c39.hpp"

/*
Виды операндов:
1) Нет
2) Регистр              a, x, y
3) адрес                $xx             адрес м.б. 8 или 16 бит
4) косв. адрес          ($xx)           адрес ячейки с целевым адресом
5) прямые данные        #$xx            константа
6) Метка                Label           целевая метка перехода
*/

// тек байт(ы) - непосредственные данные, 1 байт
static void near SetImmData(op_t &op, uchar code)
{
        op.type=o_imm;
        // оно находится всегда во втором байте
        op.offb=1;
        // размер элемента
        op.dtyp=dt_byte;
        // значение
        op.addr=op.value=code;
        // это не может быть ссылкой !
        op.flags|=OF_NUMBER;   // только число
}

// регистры считаются байтовыми
static void near SetReg(op_t &op, uchar reg_n)
{
op.type=o_reg;          // это только регистр
op.reg= reg_n;          // значение регистра
op.dtyp=dt_byte;        // размер - всегда 8 бит
}


// установить ячейку памяти
static void near SetMemVar(op_t &op, ushort addr)
{
op.type=o_mem;
op.addr=op.value=addr;
op.dtyp=dt_word;
}

// установить ячейку памяти с адресом
static void near SetMemVarI(op_t &op, ushort addr)
{
op.type=o_mem;
op.specflag1|=URR_IND;
op.addr=op.value=addr;
op.dtyp=dt_word;
}

// Установить относительный переход
static void near SetRelative(op_t &op, signed char disp)
{
op.type=o_near;
op.dtyp=dt_word;
op.offb=1;      // на самом деле не всегда так...
// рассчитаем конечное значение
op.addr=op.value=cmd.ip+cmd.size+(int32)disp;
}

// Установить абсолютный переход
static void near SetAbs(op_t &op, unsigned short disp)
{
op.type=o_near;
op.dtyp=dt_word;
op.offb=1;      // на самом деле не всегда так...
// рассчитаем конечное значение
op.addr=op.value=disp;
}


unsigned short GetWord(void)
{
unsigned short wrd;
wrd=ua_next_byte();
wrd|=((unsigned short)ua_next_byte())<<8;
return(wrd);
}

static void near ClearOperand(op_t &op)
{
op.dtyp=dt_byte;
op.type=o_void;
op.specflag1=0;
op.specflag2=0;
op.offb=0;
op.offo=0;
//op.flags=0;
op.reg=0;
op.value=0;
op.addr=0;
op.specval=0;
}


//----------------------------------------------------------------------
// анализатор
int idaapi C39_ana(void)
{
  uchar code;
  ClearOperand(cmd.Op1);
  ClearOperand(cmd.Op2);
  ClearOperand(cmd.Op3);
    // получим байт инструкции
  code = ua_next_byte();
static const unsigned char  Dt[]={
C39_brk, C39_ora, C39_mpy, C39_tip,       0, C39_ora, C39_asl, C39_rmb,  //00
C39_php, C39_ora, C39_asl, C39_jsb, C39_jpi, C39_ora, C39_asl, C39_bbr,  //08

C39_bpl, C39_ora, C39_mpa, C39_lab,       0, C39_ora, C39_asl, C39_rmb,  //10
C39_clc, C39_ora, C39_neg, C39_jsb,       0, C39_ora, C39_asl, C39_bbr,  //18

C39_jsr, C39_and, C39_psh, C39_phw, C39_bit, C39_and, C39_rol, C39_rmb,  //20
C39_plp, C39_and, C39_rol, C39_jsb, C39_bit, C39_and, C39_rol, C39_bbr,  //28

C39_bmi, C39_and, C39_pul, C39_plw,       0, C39_and, C39_rol, C39_rmb,  //30
C39_sec, C39_and, C39_asr, C39_jsb,       0, C39_and, C39_rol, C39_bbr,  //38


C39_rti, C39_eor, C39_rnd,       0,       0, C39_eor, C39_lsr, C39_rmb,  //40
C39_pha, C39_eor, C39_lsr, C39_jsb, C39_jmp, C39_eor, C39_lsr, C39_bbr,  //48

C39_bvc, C39_eor, C39_clw,       0,       0, C39_eor, C39_lsr, C39_rmb,  //50
C39_cli, C39_eor, C39_phy, C39_jsb,       0, C39_eor, C39_lsr, C39_bbr,  //58

C39_rts, C39_adc, C39_taw,       0, C39_add, C39_adc, C39_ror, C39_rmb,  //60
C39_pla, C39_adc, C39_ror, C39_jsb, C39_jmp, C39_adc, C39_ror, C39_bbr,  //68

C39_bvs, C39_adc, C39_twa,       0, C39_add, C39_adc, C39_ror, C39_rmb,  //70
C39_sei, C39_adc, C39_ply, C39_jsb, C39_jmp, C39_adc, C39_ror, C39_bbr,  //78


C39_bra, C39_sta,       0,       0, C39_sty, C39_sta, C39_stx, C39_smb,  //80
C39_dey, C39_add, C39_txa, C39_nxt, C39_sty, C39_sta, C39_stx, C39_bbs,  //88

C39_bcc, C39_sta,       0,       0, C39_sty, C39_sta, C39_stx, C39_smb,  //90
C39_tya, C39_sta, C39_txs, C39_lii,       0, C39_sta,       0, C39_bbs,  //98

C39_ldy, C39_lda, C39_ldx,       0, C39_ldy, C39_lda, C39_ldx, C39_smb,  //A0
C39_tay, C39_lda, C39_tax, C39_lan, C39_ldy, C39_lda, C39_ldx, C39_bbs,  //A8

C39_bcs, C39_lda, C39_sti,       0, C39_ldy, C39_lda, C39_ldx, C39_smb,  //B0
C39_clv, C39_lda, C39_tsx, C39_ini, C39_ldy, C39_lda, C39_ldx, C39_bbs,  //B8


C39_cpy, C39_cmp, C39_rba,       0, C39_cpy, C39_cmp, C39_dec, C39_smb,  //C0
C39_iny, C39_cmp, C39_dex, C39_phi, C39_cpy, C39_cmp, C39_dec, C39_bbs,  //C8

C39_bne, C39_cmp, C39_sba,       0, C39_exc, C39_cmp, C39_dec, C39_smb,  //D0
C39_cld, C39_cmp, C39_phx, C39_pli,       0, C39_cmp, C39_dec, C39_bbs,  //D8

C39_cpx, C39_sbc, C39_bar,       0, C39_cpx, C39_sbc, C39_inc, C39_smb,  //E0
C39_inx, C39_sbc, C39_nop, C39_lai, C39_cpx, C39_sbc, C39_inc, C39_bbs,  //E8

C39_beq, C39_sbc, C39_bas,       0,       0, C39_sbc, C39_inc, C39_smb,  //F0
C39_sed, C39_sbc, C39_plx, C39_pia,       0, C39_sbc, C39_inc, C39_bbs}; //F8
  // получим код команды
  cmd.itype=Dt[code];
  // анализируем код команды
  switch ( (cmd.itype=Dt[code]) ){
  // команда неизвестна
  case 0: return(0);
  // smb/rmb
  case C39_smb:
  case C39_rmb:         SetImmData(cmd.Op1, (code>>4) & 7);
                        SetMemVar(cmd.Op2, ua_next_byte());
                        break;
  // bbs/bbr
  case C39_bbs:
  case C39_bbr:         SetImmData(cmd.Op1, (code>>4)&7);
                        SetMemVar(cmd.Op2, ua_next_byte());
                        SetRelative(cmd.Op3,ua_next_byte());
                        break;

  // bpl/bmi/bvc/bvs/bra/bcc/bcs/bne/beq
  case C39_beq:
  case C39_bne:
  case C39_bcs:
  case C39_bcc:
  case C39_bra:
  case C39_bvs:
  case C39_bvc:
  case C39_bmi:
  case C39_bpl:         SetRelative(cmd.Op1,ua_next_byte());
                        break;
  // jsb
  case C39_jsb:         SetMemVar(cmd.Op1,0xFFE0+((code>>4) & 7)*2);
                        break;

  // ora, and, eor, adc, sta, lda, cmp, sbc
  case C39_sbc:
  case C39_cmp:
  case C39_lda:
  case C39_sta:
  case C39_adc:
  case C39_eor:
  case C39_and:
  case C39_ora: switch ( code&0x1E ){
                // 01 - xxx ($b)
                case 0x00:      SetMemVarI(cmd.Op1, ua_next_byte());
                                break;
                // 05 - xxx $b
                case 0x04:      SetMemVar(cmd.Op1, ua_next_byte());
                                break;
                // 09 - xxx #$b
                case 0x08:      SetImmData(cmd.Op1, ua_next_byte());
                                break;
                // 0D - xxx $w
                case 0x0C:      SetMemVar(cmd.Op1, GetWord());
                                break;
                // 11 - xxx ($b), x
                case 0x10:      SetMemVarI(cmd.Op1, ua_next_byte());
                                SetReg(cmd.Op2,rX);
                                break;
                // 15 - xxx $b, x
                case 0x14:      SetMemVar(cmd.Op1, ua_next_byte());
                                SetReg(cmd.Op2,rX);
                                break;
                // 19 - xxx $w, y
                case 0x18:      SetMemVar(cmd.Op1, GetWord());
                                SetReg(cmd.Op2,rY);
                                break;
                // 1d - xxx $w, x
                case 0x1C:      SetMemVar(cmd.Op1, GetWord());
                                SetReg(cmd.Op2,rX);
                                break;
                }
                break;
  // asl, rol, lsr, ror, asr
  case C39_asr:         // у этой есть только один вариант (asr a)
  case C39_ror:
  case C39_lsr:
  case C39_rol:
  case C39_asl: switch ( code&0x1C ){
                // 6 - xxx $b
                case 0x04:      SetMemVar(cmd.Op1, ua_next_byte());
                                break;
                // A - xxx a
                case 0x08:      SetReg(cmd.Op1,rA);
                                break;
                // E - xxx $w
                case 0x0C:      SetMemVar(cmd.Op1, GetWord());
                                break;
                //16 - xxx $b, x
                case 0x14:      SetMemVar(cmd.Op1, ua_next_byte());
                                SetReg(cmd.Op2,rX);
                                break;
                //1E - xxx $w, x
                case 0x1C:      SetMemVar(cmd.Op1, GetWord());
                                SetReg(cmd.Op2,rX);
                                break;
                }
                break;
  // inc, dec
  case C39_dec:
  case C39_inc: switch ( code&0x18 ){
                // e6 - xxx $b
                case 0x00:      SetMemVar(cmd.Op1, ua_next_byte());
                                break;
                // ee - xxx $w
                case 0x08:      SetMemVar(cmd.Op1, GetWord());
                                break;
                // f6 - xxx $b, x
                case 0x10:      SetMemVar(cmd.Op1, ua_next_byte());
                                SetReg(cmd.Op2,rX);
                                break;
                // fe - xxx $w, x
                case 0x18:      SetMemVar(cmd.Op1, GetWord());
                                SetReg(cmd.Op2,rX);
                                break;
                }
                break;
  // rba/sba $b, $w
  case C39_rba:
  case C39_sba:         SetImmData(cmd.Op1, ua_next_byte());
                        SetMemVar(cmd.Op2, GetWord());
                        break;
  // cpy/cpx
  case C39_cpx:
  case C39_cpy: switch ( code&0x1C ){
                //a0 - xxx #$b
                case 0x00:      SetImmData(cmd.Op1, ua_next_byte());
                                break;
                //a4 - xxx $b
                case 0x04:      SetMemVar(cmd.Op1, ua_next_byte());
                                break;
                //ac - xxx $w
                case 0x0C:      SetMemVar(cmd.Op1, GetWord());
                                break;
                //14 - xxx $b, x
                case 0x14:      SetMemVar(cmd.Op1, ua_next_byte());
                                SetReg(cmd.Op2,rX);
                                break;
                //1C - xxx $w, x
                case 0x1C:      SetMemVar(cmd.Op1, GetWord());
                                SetReg(cmd.Op2,rX);
                                break;
                }
                break;
  // lab/neg
  case C39_neg:
  case C39_lab:         SetReg(cmd.Op1,rA);
                        break;
  // jpi ($w)
  case C39_jpi:         SetMemVarI(cmd.Op1, GetWord());
                        break;
  // jsr $w
  case C39_jsr:         SetAbs(cmd.Op1, GetWord());
                        break;

  // bar/bas $w, $b ,$rel
  case C39_bar:
  case C39_bas:         SetMemVar(cmd.Op1, GetWord());
                        SetImmData(cmd.Op2, ua_next_byte());
                        SetRelative(cmd.Op3, ua_next_byte());
                        break;
  // bit
  case C39_bit:         if ( code&8 ){
                                // bit $w
                                SetMemVar(cmd.Op1, GetWord());
                        }
                        else {
                                // bit $b
                                SetMemVar(cmd.Op1,ua_next_byte());
                        }
                        break;
  // jmp
  case C39_jmp: switch ( code ){
                case 0x4C:      SetAbs(cmd.Op1, GetWord());
                                break;
                case 0x6C:      SetMemVarI(cmd.Op1, GetWord());
                                break;
                case 0x7C:      SetMemVarI(cmd.Op1, GetWord());
                                SetReg(cmd.Op2,rX);
                                break;
                }
                break;
  // sti
  case C39_sti: SetImmData(cmd.Op1,ua_next_byte());
                SetMemVar(cmd.Op2,ua_next_byte());
                break;
  // exc
  case C39_exc: SetMemVar(cmd.Op1,ua_next_byte());
                SetReg(cmd.Op2,rX);
                break;
  // add
  case C39_add: switch ( code ){
                case 0x64:      SetMemVar(cmd.Op1,ua_next_byte());
                                break;
                case 0x74:      SetMemVar(cmd.Op1,ua_next_byte());
                                SetReg(cmd.Op2,rX);
                                break;
                case 0x89:      SetImmData(cmd.Op1,ua_next_byte());
                                break;
                }
                break;
  // sty
  case C39_stx:
  case C39_ldx:
  case C39_ldy:
  case C39_sty: switch ( code&0x1C ){
                // A0   xxx #$b
                case 0x00:      SetImmData(cmd.Op1,ua_next_byte());
                                break;
                // A4   xxx $b
                case 0x04:      SetMemVar(cmd.Op1,ua_next_byte());
                                break;
                // AC   xxx $w
                case 0x0C:      SetMemVar(cmd.Op1,GetWord());
                                break;
                // B4   xxx $b, x
                case 0x14:      SetMemVar(cmd.Op1,ua_next_byte());
                                SetReg(cmd.Op2,
                                        (cmd.itype==C39_sty||
                                        cmd.itype==C39_ldy)?rX:rY);
                                break;
                // BC   xxx $w, x
                case 0x1C:      SetMemVar(cmd.Op1,GetWord());
                                SetReg(cmd.Op2,
                                        (cmd.itype==C39_sty||
                                        cmd.itype==C39_ldy)?rX:rY);
                                break;
                }
                break;
  }
  return cmd.size;
}
