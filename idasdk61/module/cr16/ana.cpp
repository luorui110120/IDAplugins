/*
 *      National Semiconductor Corporation CR16 processor module for IDA Pro.
 *      Copyright (c) 2002-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "cr16.hpp"

static uchar near Rproc(uchar code)
{
switch ( code ){
case 0x1: return(rPSR);
case 0x3: return(rINTBASE);
case 0x4: return(rINTBASEH);
case 0x5: return(rCFG);
case 0x7: return(rDSR);
case 0x9: return(rDCR);
case 0xB: return(rISP);
case 0xD: return(rCARL);
case 0xE: return(rCARH);
}
return(0);
}

// тек байт(ы) - непосредственные данные
static void near SetImmData(op_t &op, int32 code, int bits)
{
        // fix sign
        if ( code&(1<<bits))code-=1L<<(bits+1 );
        op.type=o_imm;
        // оно находится всегда во втором байте
        op.offb=1;
        // размер элемента
                op.dtyp=bits>8?(bits>16?dt_dword:dt_word):dt_byte;
        // значение
        op.addr=op.value=code;
//        // это не может быть ссылкой !
//        op.flags|=OF_NUMBER;   // только число
}

// регистры считаются байтовыми
static void near SetReg(op_t &op, uchar reg_n)
{
op.type=o_reg;          // это только регистр
op.reg= reg_n;          // значение регистра
op.dtyp=dt_byte;        // размер - всегда 8 бит
}


// установить ячейку памяти
/*static void near SetMemVar(op_t &op, ea_t addr)
{
op.type=o_mem;
op.addr=op.value=addr;
op.dtyp=dt_word;
}
*/

// Установить относительный переход
static void near SetRelative(op_t &op, int32 disp, int bits)
{
op.type=o_near;
op.dtyp=dt_word;
op.offb=0;      // на самом деле не всегда так...
// рассчитаем конечное значение
if ( disp&(1<<bits))disp-=1L<<(bits+1 );
op.addr=op.value=cmd.ip/*+cmd.size*/+disp;
}

unsigned short GetWord(void)
{
unsigned short wrd;
wrd=ua_next_byte();
wrd|=((unsigned short)ua_next_byte())<<8;
return(wrd);
}


static void near SetSL(op_t &op, unsigned short code)
{
op.reg=rR0+((code>>1)&0x0F);
op.dtyp=(code&0x2000)?dt_word:dt_byte;
if ( code&1 ){
        if ( code&0x1000 ){
                if ( code&0x800 ){
                        if ( (code&0x1F)==0x1F ){
                                // absolute addr
                                op.type=o_mem;
                                op.addr=op.value=GetWord()|
                                        (((uint32)code&0x600)<<11);
                        }
                        else{   // reg pair
                                op.type=o_displ;
                                op.addr=op.value=GetWord()|
                                        (((uint32)code&0x600)<<11);
                                op.specflag1|=URR_PAIR;
                        }
                }
                else{           // reg base
                                op.type=o_displ;
                                op.addr=op.value=GetWord()|
                                        (((uint32)code&0x600)<<11);
                }
        }
        else{   // Offset
                op.type=o_displ;
                op.addr=op.value=((code>>8)&0x1E)|1;
        }
}
else{
        op.type=o_displ;
        op.addr=op.value=(code>>8)&0x1E;
}
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

static const unsigned char Ops[16]={
CR16_addb,  CR16_addub, 0        , CR16_mulb,
CR16_ashub, CR16_lshb,  CR16_xorb, CR16_cmpb,
CR16_andb,  CR16_addcb, CR16_br,   CR16_tbit,
CR16_movb,  CR16_subcb, CR16_orb,  CR16_subb};


//----------------------------------------------------------------------
// анализатор
int idaapi CR16_ana(void)
{
  ushort code;
  uchar  WordFlg;
  uchar OpCode;
  uchar Oper1;
  uchar Oper2;
  ClearOperand(cmd.Op1);
  ClearOperand(cmd.Op2);
  if ( cmd.ip&1)return(0 );
  // получим cлово инструкции
  code = GetWord();

  WordFlg       = (code>>13)&1;
  OpCode        = (code>>9)&0x0F;
  Oper1           = (code>>5)&0x0F;
  Oper2           = (code>>1)&0x0F;


  switch ( (code>>14)&3 ){
  // register-register op and special OP
  case 0x01:    if ( code&1 ){
                        // 01xxxxxxxxxxxxx1
                        switch ( (cmd.itype=Ops[OpCode]) ){
                        case 0:         return(0);
                        // branch's
                        case CR16_br:   if ( WordFlg ){
                                                cmd.itype=CR16_jal;
                                                SetReg(cmd.Op1,rR0+Oper1);
                                                SetReg(cmd.Op2,rR0+Oper2);
                                        }
                                        else{
                                                cmd.itype=CR16_jeq+Oper1;
                                                SetReg(cmd.Op1,rR0+Oper2);
                                        }
                                        break;
                        // Special tbit
                        case CR16_tbit: if ( WordFlg==0)return(0 );
                                        cmd.itype--;
                        // all other cmds
                        default:        // fix word operations
                                        if ( WordFlg ) cmd.itype++;
                                        // Setup register OP
                                        SetReg(cmd.Op2,rR0+Oper1);
                                        // Setup register OP
                                        SetReg(cmd.Op1,rR0+Oper2);
                                        break;
                        }
                }
                else{   // 01xxxxxxxxxxxxx0
                        if ( WordFlg ){
                                // 011xxxxxxxxxxxx0
                                static const unsigned char SCmd[16]={
                                CR16_mulsb, CR16_mulsw, CR16_movd, CR16_movd,
                                CR16_movxb, CR16_movzb, CR16_push, CR16_seq,
                                CR16_lpr,   CR16_spr,   0,         0,
                                CR16_retx,  CR16_excp,  CR16_di,   CR16_wait
                                };
                                switch ( (cmd.itype=SCmd[OpCode]) ){
                                case 0:         return(0);

                                case CR16_push: { static const unsigned char
                                                        PQ[4]={
                                                  CR16_push,CR16_pop,
                                                  CR16_popret,CR16_popret};
                                                cmd.itype=PQ[Oper1>>2];
                                                SetReg(cmd.Op2,rR0+Oper2);
                                                SetImmData(cmd.Op1,Oper1&3,4);
                                                break;
                                                }

                                case CR16_mulsw:SetReg(cmd.Op2,rR0+Oper1);
                                                SetReg(cmd.Op1,rR0+Oper2);
                                                cmd.Op2.specflag1|=URR_PAIR;
                                                break;

                                case CR16_movd: SetReg(cmd.Op2,rR0+Oper2);
                                                cmd.Op2.specflag1|=URR_PAIR;
                                                // !!!! ADD HIIIII ?!?!?!?
                                                SetImmData(cmd.Op1,
                                                        GetWord()
                                                        ,20);
                                                break;
                                case CR16_excp: if ( Oper1!=0x0F)return(0 );
                                                SetImmData(cmd.Op1,Oper2,4);
                                                break;

                                case CR16_retx: if ( Oper1!=0x0F)return(0 );
                                                if ( Oper2!=0x0F)return(0 );
                                                break;

                                case CR16_wait: if ( Oper1==0x0F ){
                                                   if ( Oper2==0x0F )break;
                                                   if ( Oper2==0x03 ){
                                                        cmd.itype=CR16_eiwait;
                                                        break;
                                                   }
                                                }
                                                if ( (code&0x19E)==0x84 ){
                                                        cmd.itype=CR16_storm;
                                                        SetImmData(cmd.Op1,(Oper2&3)+1,8);
                                                        break;
                                                }
                                                if ( (code&0x19E)==0x04 ){
                                                        cmd.itype=CR16_loadm;
                                                        SetImmData(cmd.Op1,(Oper2&3)+1,8);
                                                        break;
                                                }
                                                if ( (Oper2&0x6)==0 ){
                                                        cmd.itype=CR16_muluw;
                                                        SetReg(cmd.Op2,rR0+Oper1);
                                                        SetReg(cmd.Op1,rR0+Oper2);
                                                        cmd.Op2.specflag1|=URR_PAIR;
                                                        break;
                                                }

                                                return(0);

                                case CR16_di:   if ( Oper2!=0x0F)return(0 );
                                                switch ( Oper1 ){
                                                case 0x0F:cmd.itype=CR16_ei;
                                                case 0x0E:break;
                                                default:  return(0);
                                                }
                                                break;

                                case CR16_seq:  SetReg(cmd.Op1,rR0+Oper2);
                                                if ( Oper1>0x0D)return(0 );
                                                cmd.itype=CR16_seq+Oper1;
                                                break;

                                case CR16_lpr:  SetReg(cmd.Op1,rR0+Oper2);
                                                Oper1=Rproc(Oper1);
                                                if ( Oper1==0)return(0 );
                                                SetReg(cmd.Op2,Oper1);
                                                break;

                                case CR16_spr:  SetReg(cmd.Op2,rR0+Oper2);
                                                Oper1=Rproc(Oper1);
                                                if ( Oper1==0)return(0 );
                                                SetReg(cmd.Op1,Oper1);
                                                break;

                                default:        SetReg(cmd.Op2,rR0+Oper1);
                                                SetReg(cmd.Op1,rR0+Oper2);
                                                break;
                                }
                        }
                        else{   // jump's
                                // 010xxxxxxxxxxxx0
                                cmd.itype=CR16_beq+Oper1;
                                SetRelative(cmd.Op1,(code&0x1E)|(OpCode<<5),8);
                        }
                }
                break;

  // short immediate-register (two word)
  case 0x00:    switch ( (cmd.itype=Ops[OpCode]) ){
                case 0:         return(0);
                // branch's
                case CR16_br:   if ( code&1 ){
                                        static const unsigned char BQ[4]={
                                        CR16_beq0b,CR16_beq1b,
                                        CR16_bne0b,CR16_bne1b};
                                        cmd.itype=BQ[(Oper1>>1)&3];
                                        if ( WordFlg )cmd.itype++;
                                        SetReg(cmd.Op1,rR0+(Oper1&0x9));
                                        SetRelative(cmd.Op1,code&0x1E,5);
                                }
                                else
                                if ( WordFlg ){
                                        cmd.itype=CR16_bal;
                                        SetReg(cmd.Op1,rR0+Oper1);
                                        if ( (code&0x0F)==0x0E ){
                                                SetRelative(cmd.Op2,
                                                        GetWord()|
                                                        (((uint32)code&0x10)<<12),
                                                        16);
                                                                                                cmd.Op2.addr=
                                                                                                cmd.Op2.value=cmd.Op2.addr&0x1FFFF;
                                                                                }
                                        else    SetRelative(cmd.Op2,code&0x1F, 4);
                                }
                                else{
                                        cmd.itype=CR16_beq+Oper1;
                                        if ( (code&0x0F)==0x0E ){
                                                SetRelative(cmd.Op1,
                                                        GetWord()|
                                                        (((uint32)code&0x10)<<12),
                                                        16);
                                                                                                cmd.Op1.addr=
                                                                                                cmd.Op1.value=cmd.Op2.addr&0x1FFFF;
                                                                                }
                                        else    SetRelative(cmd.Op1,code&0x1F, 4);
                                }
                                break;

                // Special tbit
                case CR16_tbit: if ( WordFlg==0)return(0 );
                                cmd.itype--;
                // all other cmds
                default:        // fix word operations
                                if ( WordFlg ) cmd.itype++;
                                // Setup register OP
                                SetReg(cmd.Op2,rR0+Oper1);
                                // Setup immediate
                                if ( (code&0x1F)==0x11 )
                                        SetImmData(cmd.Op1,GetWord(),15);
                                else    SetImmData(cmd.Op1,code&0x1F, 4);
                                break;
                }
                break;

  // LOADi
  case 0x02:    cmd.itype=WordFlg?CR16_loadw:CR16_loadb;
                SetReg(cmd.Op2,rR0+Oper1);
                SetSL(cmd.Op1,code);
                break;
  // STORi
  case 0x3:     cmd.itype=WordFlg?CR16_storw:CR16_storb;
                SetReg(cmd.Op1,rR0+Oper1);
                SetSL(cmd.Op2,code);
                break;
  }
  return cmd.size;
}
