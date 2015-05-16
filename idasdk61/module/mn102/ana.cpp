/*
 *      Panasonic MN102 (PanaXSeries) processor module for IDA Pro.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "pan.hpp"

// только для внутреннего использования
static uint32 LoadData(int bytes)
{
uint32 dt=0;
int i;
        // загрузим данные
        for(i=0;i<bytes;i++){
                uint32 nb=ua_next_byte();
                dt|=nb<<(8*i);
        }
        return(dt);
}

// поставить метку по смещению (+извл. байт)
static void SetLabel(op_t &op, int bytes)
{
uint32 off;
//        char cc[20];
        op.type=o_near;
        // загрузим данные
        off=LoadData(bytes);
        // распространим знак
        switch ( bytes ){
        // 1 байт
        case 1: if ( off&0x000080L )off|=~0x00007FL;
                break;

        // 2 байта
        case 2: if ( off&0x008000L )off|=~0x007FFFL;
                break;

        // 3 байта
        case 3: if ( off&0x800000L )off|=~0x7FFFFFL;
                break;
        }
//        sprintf(cc,"%lx",off);
//        msg(cc);
        op.addr=op.value=(off+(uint32)cmd.size+cmd.ea) & 0xFFFFFFL;
//        sprintf(cc,"==%lx",op.value);
//        msg(cc);
//        sprintf(cc,"==%lx",cmd.ea);
//        msg(cc);
//        msg("\n");

}


// установить значение непосредственным, только числовым
static void SetImm(op_t &op, int bytes)
{
  op.type=o_imm;                        // непосредственное
  op.dtyp=dt_dword;                     // реально - не совсем байт
  op.addr=op.value=LoadData(bytes);     // значение числа
}

static void SetImmC(op_t &op, int Val)
{
  op.type=o_imm;                        // непосредственное
  op.dtyp=dt_dword;                     // реально - не совсем байт
  op.flags|=OF_NUMBER;                  // только число
  op.addr=op.value=Val;                 // значение числа
}

// адресация регистром
static void SetReg(op_t &op,uchar Reg)
{
        op.type=o_reg;
        op.reg=Reg;
        op.addr=op.value=0;
}

// косвенная адресация
static void SetRReg(op_t &op,uchar Reg)
{
        op.type=o_reg;
        op.reg=Reg|0x80;        // косвенная адресация
        op.addr=op.value=0;
}

// косвенная адресация с доп. смещением
static void SetDisplI(op_t &op,uchar Reg, uchar RegI)
{
        op.type=o_reg;
        op.reg=(Reg&0x0F)|0x90|((RegI&3)<<5);
        op.addr=op.value=0;
}

// косвенная адресация с доп. смещением
static void SetDispl(op_t &op,uchar Reg, int OffSize)
{
        op.type=o_displ;
                op.dtyp=dt_dword;                     // реально - не совсем байт
        op.reg=Reg;
        op.addr=op.value=LoadData(OffSize);
}


// указатель на память
// AddrSize - размер адреса
// DataSize - размер пересылаемых данных
static void SetMem(op_t &op, int AddrSize, uchar DataSize)
{
        op.type=o_mem;
        op.addr=op.value=LoadData(AddrSize);
        op.dtyp=DataSize;
}


//----------------------------------------------------------------------
// анализатор
int idaapi mn102_ana(void)
{
        uchar R1, R2;
        // получим первый байт инструкции
        uchar code = ua_next_byte();
        // анализируем старшую часть
        R1=code&3;
        R2=(code>>2)&3;
        cmd.Op1.specflag1=0;
        cmd.Op2.specflag1=0;
        switch ( code>>4 ){

        // mov  Dm, (An)
        case 0x00:      cmd.itype=mn102_mov;
                        SetReg(cmd.Op1,R1+rD0);
                        SetRReg(cmd.Op2,R2+rA0);
                        break;

        // movb Dm, (An)
        case 0x01:      cmd.itype=mn102_movb;
                        SetReg(cmd.Op1,R1+rD0);
                        SetRReg(cmd.Op2,R2+rA0);
                        break;

        // mov (An), Dm
        case 0x02:      cmd.itype=mn102_mov;
                        SetReg(cmd.Op2,R1+rD0);
                        SetRReg(cmd.Op1,R2+rA0);
                        break;

        // movbu (An), Dm
        case 0x03:      cmd.itype=mn102_movbu;
                        SetReg(cmd.Op2,R1+rD0);
                        SetRReg(cmd.Op1,R2+rA0);
                        break;

        // mov  Dm, (d8,An)
        case 0x04:      cmd.itype=mn102_mov;
                        SetReg(cmd.Op1,R1+rD0);
                        SetDispl(cmd.Op2,R2+rA0,1);
                        break;

        // mov  An, (d8,An);
        case 0x05:      cmd.itype=mn102_mov;
                        SetReg(cmd.Op1,R1+rA0);
                        SetDispl(cmd.Op2,R2+rA0,1);
                        break;

        // mov (d8,An), Dm
        case 0x06:      cmd.itype=mn102_mov;
                        SetReg(cmd.Op2,R1+rD0);
                        SetDispl(cmd.Op1,R2+rA0,1);
                        break;

        // mov  (d8,An), Am
        case 0x07:      cmd.itype=mn102_mov;
                        SetReg(cmd.Op2,R1+rA0);
                        SetDispl(cmd.Op1,R2+rA0,1);
                        break;

        // mov Dn, Dm или mov imm8,Dn
        case 0x08:      cmd.itype=mn102_mov;
                        if ( (code&3)==((code>>2)&3) ){
                                // mov imm, Dn
                                SetImm(cmd.Op1,1);
                                SetReg(cmd.Op2,R1+rD0);
                        }
                        else{
                                SetReg(cmd.Op1,R2+rD0);
                                SetReg(cmd.Op2,R1+rD0);
                        }
                        break;

        // add Dn, Dm
        case 0x09:      cmd.itype=mn102_add;
                        SetReg(cmd.Op1,R2+rD0);
                        SetReg(cmd.Op2,R1+rD0);
                        break;

        // Sub Dn,Dm
        case 0x0A:      cmd.itype=mn102_sub;
                        SetReg(cmd.Op1,R2+rD0);
                        SetReg(cmd.Op2,R1+rD0);
                        break;

        // Extx* Dn
        case 0x0B:      switch ( code&0xC ){
                        // extx
                        case 0x00:      cmd.itype=mn102_extx;
                                        break;
                        case 0x04:      cmd.itype=mn102_extxu;
                                        break;
                        case 0x08:      cmd.itype=mn102_extxb;
                                        break;
                        case 0x0C:      cmd.itype=mn102_extxbu;
                                        break;
                        }
                        SetReg(cmd.Op1,R1+rD0);
                        break;

        // mov* Dn, (mem) и
        case 0x0C:      switch ( code&0xC ){
                        // mov Dn, (abs)
                        case 0x00:      cmd.itype=mn102_mov;
                                        SetReg(cmd.Op1,R1+rD0);
                                        SetMem(cmd.Op2, 2, dt_word);
                                        break;

                        // movb Dn, (abs)
                        case 0x04:      cmd.itype=mn102_movb;
                                        SetReg(cmd.Op1,R1+rD0);
                                        SetMem(cmd.Op2, 2, dt_byte);
                                        break;

                        // mov (abs), Dn
                        case 0x08:      cmd.itype=mn102_mov;
                                        SetReg(cmd.Op2,R1+rD0);
                                        SetMem(cmd.Op1, 2, dt_word);
                                        break;

                        // movbu (abs), Dn
                        case 0x0C:      cmd.itype=mn102_movbu;
                                        SetReg(cmd.Op2,R1+rD0);
                                        SetMem(cmd.Op1, 2, dt_byte);
                                        break;
                        }
                        break;
        // add/cmp,mov
        case 0x0D:      switch ( code&0xC ){
                        // add imm8, An
                        case 0x00:      SetReg(cmd.Op2,R1+rA0);
                                        cmd.itype=mn102_add;
                                        SetImm(cmd.Op1, 1);
                                        break;

                        // add imm8, Dn
                        case 0x04:      SetReg(cmd.Op2,R1+rD0);
                                        cmd.itype=mn102_add;
                                        SetImm(cmd.Op1, 1);
                                        break;

                        //  cmp imm8, Dn
                        case 0x08:      SetReg(cmd.Op2,R1+rD0);
                                        cmd.itype=mn102_cmp;
                                        SetImm(cmd.Op1, 1);
                                        break;

                        // mov  imm16, An
                        case 0x0c:      SetReg(cmd.Op2,R1+rA0);
                                        cmd.itype=mn102_mov;
                                        SetImm(cmd.Op1, 2);
                                        cmd.Op1.specflag1=URB_ADDR;
                                        break;
                        }
                        break;

        // Jmps
        case 0x0E:      {static const uchar Cmd[16]={
                                mn102_blt,mn102_bgt,mn102_bge,mn102_ble,
                                mn102_bcs,mn102_bhi,mn102_bcc,mn102_bls,
                                mn102_beq,mn102_bne,mn102_bra,mn102_rti,
                                mn102_cmp,mn102_cmp,mn102_cmp,mn102_cmp};
                                cmd.itype=Cmd[code&0xF];
                                switch ( cmd.itype ){
                                // rti
                                case mn102_rti: break;
                                // cmp imm16, An
                                case mn102_cmp: SetReg(cmd.Op2,R1+rA0);
                                                SetImm(cmd.Op1, 2);
                                                break;
                                // jmps
                                default:        SetLabel(cmd.Op1,1);
                                                break;
                                }
                                break;
                        }
        // ExtCodes
        case 0x0F:      switch ( code&0xF ){
                        // Набор F0
                        case 0x00:      code=ua_next_byte();
                                        R1=(code&3);
                                        R2=(code>>2)&3;
                                        switch ( code&0xC0 ){
                                        // комплексный наборчик
                                        case 0x00:      switch ( code&0x30 ){
                                                        // еще один наборчик
                                                        case 0x00:      if ( code&2)return(0 );
                                                                        SetRReg(cmd.Op1,R2+rA0);
                                                                        if ( code&1 )cmd.itype=mn102_jsr;
                                                                        else    cmd.itype=mn102_jmp;
                                                                        break;
                                                        case 0x10:      return(0);

                                                        case 0x20:      cmd.itype=mn102_bset;
                                                                        SetReg(cmd.Op1,R1+rD0);
                                                                        SetRReg(cmd.Op2,R2+rA0);
                                                                        break;

                                                        case 0x30:      cmd.itype=mn102_bclr;
                                                                        SetReg(cmd.Op1,R1+rD0);
                                                                        SetRReg(cmd.Op2,R2+rA0);
                                                                        break;
                                                        }
                                                        break;

                                        // movb (Di,An), Dm
                                        case 0x40:      cmd.itype=mn102_movb;
                                                        SetReg(cmd.Op2,R1+rD0);
                                                        SetDisplI(cmd.Op1,R2+rA0,code>>4);
                                                        break;
                                        // movbu (Di,An), Dm
                                        case 0x80:      cmd.itype=mn102_movbu;
                                                        SetReg(cmd.Op2,R1+rD0);
                                                        SetDisplI(cmd.Op1,R2+rA0,code>>4);
                                                        break;
                                        // movb Dm, (Di, An)
                                        case 0xC0:      cmd.itype=mn102_movb;
                                                        SetReg(cmd.Op1,R1+rD0);
                                                        SetDisplI(cmd.Op2,R2+rA0,code>>4);
                                                        break;
                                        }
                                        break;
                        // Набор F1
                        case 0x01:      cmd.itype=mn102_mov;
                                        code=ua_next_byte();
                                        R1=(code&3);
                                        R2=(code>>2)&3;
                                        switch ( code&0xC0 ){
                                        // mov (Di, An), Am
                                        case 0x00:      SetReg(cmd.Op2,R1+rA0);
                                                        SetDisplI(cmd.Op1,R2+rA0, code>>4);
                                                        break;

                                        // mov (Di,An), Dm
                                        case 0x40:      SetReg(cmd.Op2,R1+rD0);
                                                        SetDisplI(cmd.Op1,R2+rA0, code>>4);
                                                        break;

                                        // mov Am, (Di, An)
                                        case 0x80:      SetReg(cmd.Op1,R1+rD0);
                                                        SetDisplI(cmd.Op2,R2+rA0, code>>4);
                                                        break;

                                        // mov Dm, (Di, An);
                                        case 0xC0:      SetReg(cmd.Op1,R1+rD0);
                                                        SetDisplI(cmd.Op2,R2+rA0, code>>4);
                                                        break;
                                        }
                                        break;
                        // набор F2
                        case 0x02:      code=ua_next_byte();
                                        R1=(code&3);
                                        R2=(code>>2)&3;
                                        {static const uchar Cmd[16]={
                                                mn102_add, mn102_sub, mn102_cmp,mn102_mov,
                                                mn102_add, mn102_sub, mn102_cmp,mn102_mov,
                                                mn102_addc,mn102_subc,0,        0,
                                                mn102_add, mn102_sub, mn102_cmp,mn102_mov};
                                                if ( (cmd.itype=Cmd[code>>4])==0)return(0 );
                                                switch ( code&0xC0 ){
                                                case 0x00:      SetReg(cmd.Op1,R2+rD0);
                                                                SetReg(cmd.Op2,R1+rA0);
                                                                break;

                                                case 0x40:      SetReg(cmd.Op1,R2+rA0);
                                                                SetReg(cmd.Op2,R1+rA0);
                                                                break;

                                                case 0x80:      SetReg(cmd.Op1,R2+rD0);
                                                                SetReg(cmd.Op2,R1+rD0);
                                                                break;

                                                case 0xC0:      SetReg(cmd.Op1,R2+rA0);
                                                                SetReg(cmd.Op2,R1+rD0);
                                                                break;
                                                }
                                        }
                                        break;
                        // набор F3
                        case 0x03:      code=ua_next_byte();
                                        R1=(code&3);
                                        R2=(code>>2)&3;
                                        SetReg(cmd.Op1,R2+rD0);
                                        SetReg(cmd.Op2,R1+rD0);
                                        {static const uchar Cmd[16]={
                                        mn102_and,mn102_or,  mn102_xor, mn102_rol,
                                        mn102_mul,mn102_mulu,mn102_divu,0,
                                        0,        mn102_cmp, 0,         0,
                                        mn102_ext,mn102_mov,mn102_not,255};
                                        switch ( cmd.itype=Cmd[code>>4] ){
                                        // ошибочный код
                                        case 0: return(0);
                                        // сдвиги
                                        case mn102_rol: SetReg(cmd.Op1,R1+rD0);
                                                        cmd.Op2.type=o_void;
                                                        {static const uchar Cmd2[4]={mn102_rol,mn102_ror,mn102_asr,mn102_lsr};
                                                        cmd.itype=Cmd2[(code>>2)&3];
                                                        }
                                                        break;
                                        //
                                        case mn102_ext: if ( code&2)return(0 );
                                                        if ( code&1 ){
                                                                cmd.Op2.type=o_void;
                                                        }
                                                        else{
                                                                cmd.itype=mn102_mov;
                                                                SetReg(cmd.Op2,rMDR);
                                                        }
                                                        break;

                                        case mn102_mov: if ( R1!=0)return(0 );
                                                        SetReg(cmd.Op2,rPSW);
                                                        break;

                                        case mn102_not: switch ( R2 ){
                                                        case 0: cmd.itype=mn102_mov;
                                                                SetReg(cmd.Op1,rMDR);
                                                                break;
                                                        case 1: cmd.Op2.type=o_void;
                                                                SetReg(cmd.Op1,R1+rD0);
                                                                break;
                                                        default:return(0);
                                                        }
                                                        break;

                                        case 255:       switch ( R2 ){
                                                        case 0: cmd.itype=mn102_mov;
                                                                SetReg(cmd.Op1,rPSW);
                                                                break;
                                                        case 3: cmd.Op2.type=cmd.Op1.type=o_void;
                                                                switch ( R1 ){
                                                                case 0: cmd.itype=mn102_pxst;
                                                                        break;
                                                                // F3, FE
                                                                case 2: { static const uchar Cmd[4]={
                                                                        mn102_tbz, mn102_tbnz,
                                                                        mn102_bset, mn102_bclr};
                                                                        code=ua_next_byte();
                                                                        if ( (code<0xC0) || (code>=0xE0)) return(0 );
                                                                        cmd.itype=Cmd[(code>>3)&3];
                                                                        SetImmC(cmd.Op1,1<<(code&7));
                                                                        SetMem(cmd.Op2, 3, dt_byte);
                                                                        // если переход - метка
                                                                        if ( (code&0xF0)==0xC0)SetLabel(cmd.Op3,1 );
                                                                        }
                                                                        break;
                                                                // F3, FF
                                                                case 3: { static const uchar Cmd[4]={
                                                                        mn102_tbz, mn102_bset,
                                                                        mn102_tbnz, mn102_bclr};
                                                                        code=ua_next_byte();
                                                                        if ( (code<0x80) || (code>=0xC0)) return(0 );
                                                                        cmd.itype=Cmd[(code>>4)&3];
                                                                        SetImmC(cmd.Op1,1<<(code&7));
                                                                        SetDispl(cmd.Op2,(code&0x8)?rA3:rA2, 1);
                                                                        cmd.Op3.dtyp=dt_byte;
                                                                        // если переход - метка
                                                                        if ( (code&0x10)==0)SetLabel(cmd.Op3,1 );
                                                                        }
                                                                        break;
                                                                default: return(0);
                                                                }
                                                                break;
                                                        default:return (0);
                                                        }
                                                        break;
                                        //Все остальные не требует обработки
                                        default:        break;
                                        }
                                        }
                                        break;

                        // набор F4 - 5 байт
                        case 0x04:      code=ua_next_byte();
                                        R1=(code&3);
                                        R2=(code>>2)&3;

                                        switch ( code&0xF0 ){
                                        // mov Dm, (D24,An)
                                        case 0x00:      cmd.itype=mn102_mov;
                                                        SetReg(cmd.Op1,R1+rD0);
                                                        SetDispl(cmd.Op2,R2+rA0,3);
                                                        break;

                                        case 0x10:      cmd.itype=mn102_mov;
                                                        SetReg(cmd.Op1,R1+rA0);
                                                        SetDispl(cmd.Op2,R2+rA0,3);
                                                        break;

                                        case 0x20:      cmd.itype=mn102_movb;
                                                        SetReg(cmd.Op1,R1+rD0);
                                                        SetDispl(cmd.Op2,R2+rA0,3);
                                                        break;

                                        case 0x30:      cmd.itype=mn102_movx;
                                                        SetReg(cmd.Op1,R1+rD0);
                                                        SetDispl(cmd.Op2,R2+rA0,3);
                                                        break;

                                        case 0x40:      switch ( R2 ){
                                                        case 0: cmd.itype=mn102_mov;
                                                                SetMem(cmd.Op2,3,dt_dword);
                                                                SetReg(cmd.Op1,R1+rD0);
                                                                break;

                                                        case 1: cmd.itype=mn102_movb;
                                                                SetMem(cmd.Op2,3,dt_byte);
                                                                SetReg(cmd.Op1,R1+rD0);
                                                                break;

                                                        default:if ( (code!=0x4B)&&(code!=0x4F))return(0 );
                                                                cmd.itype=(code==0x4B)?mn102_bset:mn102_bclr;
                                                                SetMem(cmd.Op2,3,dt_byte);
                                                                SetImm(cmd.Op1,1);
                                                                break;
                                                        }
                                                        break;

                                        case 0x50:      if ( R2!=0)return(0 );
                                                        cmd.itype=mn102_mov;
                                                        SetReg(cmd.Op1,R1+rA0);
                                                        SetMem(cmd.Op1,3,dt_tbyte);
                                                        break;

                                        case 0x60:      SetImm(cmd.Op1,3);
                                                        SetReg(cmd.Op2, R1+((R2&1)?rA0:rD0));
                                                        cmd.itype=(R2&2)?mn102_sub:mn102_add;
                                                        break;

                                        case 0x70:      SetImm(cmd.Op1,3);
                                                                                                                cmd.Op1.specflag1=URB_ADDR;
                                                        SetReg(cmd.Op2,R1+((R2&1)?rA0:rD0));
                                                        cmd.itype=(R2&2)?mn102_cmp:mn102_mov;
                                                        break;

                                        case 0x80:      cmd.itype=mn102_mov;
                                                        SetDispl(cmd.Op1,R2+rA0,3);
                                                        SetReg(cmd.Op2,R1+rD0);
                                                        break;

                                        case 0x90:      cmd.itype=mn102_movbu;
                                                        SetDispl(cmd.Op1,R2+rA0,3);
                                                        SetReg(cmd.Op2,R1+rD0);
                                                        break;

                                        case 0xA0:      cmd.itype=mn102_movb;
                                                        SetDispl(cmd.Op1,R2+rA0,3);
                                                        SetReg(cmd.Op2,R1+rD0);
                                                        break;

                                        case 0xB0:      cmd.itype=mn102_movx;
                                                        SetDispl(cmd.Op1,R2+rA0,3);
                                                        SetReg(cmd.Op2,R1+rD0);
                                                        break;

                                        case 0xC0:      SetReg(cmd.Op2,R1+rD0);
                                                        switch ( R2 ){
                                                        case 0: cmd.itype=mn102_mov;
                                                                SetMem(cmd.Op1,3,dt_word);
                                                                break;

                                                        case 1: cmd.itype=mn102_movb;
                                                                SetMem(cmd.Op1,3,dt_byte);
                                                                break;

                                                        case 2: cmd.itype=mn102_movbu;
                                                                SetMem(cmd.Op1,3,dt_byte);
                                                                break;

                                                        default: return(0);
                                                        }
                                                        break;

                                        case 0xD0:      if ( R2!=0)return(0 );
                                                        cmd.itype=mn102_mov;
                                                        SetMem(cmd.Op1,3,dt_tbyte);
                                                        SetReg(cmd.Op2,R1+rA0);
                                                        break;

                                        case 0xE0:      switch ( code ){
                                                        case 0xE0:      cmd.itype=mn102_jmp;
                                                                        SetLabel(cmd.Op1,3);
                                                                        break;

                                                        case 0xE1:      cmd.itype=mn102_jsr;
                                                                        SetLabel(cmd.Op1,3);
                                                                        break;
                                                        case 0xE3:
                                                        case 0xE7:      cmd.itype=(code==0xE3)?mn102_bset:mn102_bclr;
                                                                        SetMem(cmd.Op2,2,dt_byte);
                                                                        SetImmC(cmd.Op1,1);
                                                                        break;

                                                        default:        if ( code<0xE8)return(0 );
                                                                        cmd.itype=(code&0x4)?mn102_bclr:mn102_bset;
                                                                        SetImmC(cmd.Op1,1);
                                                                        SetDispl(cmd.Op2,rA0+(code&3),1);
                                                                        break;
                                                        }
                                                        break;

                                        case 0xF0:      cmd.itype=mn102_mov;
                                                        SetDispl(cmd.Op1,R2+rA0,3);
                                                        SetReg(cmd.Op2,R1+rA0);
                                                        break;
                                        }
                                        break;
                        // набор F5
                        case 0x05:      code=ua_next_byte();
                                        R1=(code&3);
                                        R2=(code>>2)&3;
                                        switch ( code&0xF0 ){
                                        case 0x00:      {static const uchar  Cmd[4]={
                                                                mn102_and,mn102_btst,mn102_or,mn102_addnf};
                                                        SetImm(cmd.Op1,1);
                                                        SetReg(cmd.Op2,R1+rD0);
                                                        cmd.itype=Cmd[R2];
                                                        }
                                                        break;
                                        // movb Dm,(d8,An)
                                        case 0x10:      cmd.itype=mn102_movb;
                                                        SetReg(cmd.Op1,R1+rD0);
                                                        SetDispl(cmd.Op2,R2+rA0,1);
                                                        break;

                                        // movb (d8,An), Dm
                                        case 0x20:      cmd.itype=mn102_movb;
                                                        SetReg(cmd.Op2,R1+rD0);
                                                        SetDispl(cmd.Op1,R2+rA0,1);
                                                        break;
                                        //movbu (d8,An), Dm
                                        case 0x30:      cmd.itype=mn102_movbu;
                                                        SetReg(cmd.Op2,R1+rD0);
                                                        SetDispl(cmd.Op1,R2+rA0,1);
                                                        break;
                                        // mulql dn, dm
                                        case 0x40:      code=ua_next_byte();
                                                        if ( code>1)return(0 );
                                                        cmd.itype=(code==0)?mn102_mulql:mn102_mulqh;
                                                        SetReg(cmd.Op1,R2+rD0);
                                                        SetReg(cmd.Op2,R1+rD0);
                                                        break;

                                        // movx Dm, (d8,An)
                                        case 0x50:      cmd.itype=mn102_movx;
                                                        SetReg(cmd.Op1,R1+rD0);
                                                        SetDispl(cmd.Op2,R2+rA0,1);
                                                        break;
                                        // mulq dn, dm
                                        case 0x60:      code=ua_next_byte();
                                                        if ( code!=0x10)return(0 );
                                                        cmd.itype=mn102_mulq;
                                                        SetReg(cmd.Op1,R2+rD0);
                                                        SetReg(cmd.Op2,R1+rD0);
                                                        break;

                                        // movx (d8,An), Dm
                                        case 0x70:      cmd.itype=mn102_movx;
                                                        SetDispl(cmd.Op1,R2+rA0,1);
                                                        SetReg(cmd.Op2,R1+rD0);
                                                        break;
                                        case 0x80:
                                        case 0x90:
                                        case 0xA0:
                                        case 0xB0:      {static const uchar Cmd[4]={
                                                        mn102_tbz, mn102_bset,mn102_tbnz,mn102_bclr};
                                                        cmd.itype=Cmd[(code>>4)&3];
                                                        SetImmC(cmd.Op1,1<<(code&7));
                                                        SetDispl(cmd.Op2,(code&0x8)?rA1:rA0,1);
                                                        if ( (code&0x10)==0)SetLabel(cmd.Op3,1 );
                                                        }
                                                        break;
                                        case 0xC0:
                                        case 0xD0:      {static const uchar Cmd[4]={
                                                        mn102_tbz, mn102_tbnz, mn102_bset,mn102_bclr};
                                                        cmd.itype=Cmd[(code>>3)&3];
                                                        SetImmC(cmd.Op1,1<<(code&7));
                                                        SetMem(cmd.Op2,2,dt_byte);
                                                        if ( (code&0x10)==0)SetLabel(cmd.Op3,1 );
                                                        }
                                                        break;

                                        case 0xE0:      {static const uchar Cmd[16]={
                                                        mn102_bltx,mn102_bgtx,mn102_bgex,mn102_blex,
                                                        mn102_bcsx,mn102_bhix,mn102_bccx,mn102_blsx,
                                                        mn102_beqx,mn102_bnex,0,0,
                                                        mn102_bvcx,mn102_bvsx,mn102_bncx,mn102_bnsx};
                                                        if ( (cmd.itype=Cmd[code&0xF])==0)return(0 );
                                                        SetLabel(cmd.Op1,1);
                                                        }
                                                        break;
                                        case 0xF0:      if ( (code<0xFC)&&(code>0xF8))return(0 );
                                                        if ( code>=0xFC ){
                                                                static const uchar Cmd[4]={
                                                                mn102_bvc,mn102_bvs,mn102_bnc,mn102_bns};
                                                                cmd.itype=Cmd[R1];
                                                                SetLabel(cmd.Op1,1);
                                                                }
                                                        else{code=ua_next_byte();
                                                                switch ( code ){
                                                                case 0x4:cmd.itype=mn102_mulql;
                                                                         SetImm(cmd.Op1,1);
                                                                         SetReg(cmd.Op2,R1+rD0);
                                                                         break;
                                                                case 0x5:cmd.itype=mn102_mulqh;
                                                                         SetImm(cmd.Op1,1);
                                                                         SetReg(cmd.Op2,R1+rD0);
                                                                         break;
                                                                case 0x8:cmd.itype=mn102_mulql;
                                                                         SetImm(cmd.Op1,2);
                                                                         SetReg(cmd.Op2,R1+rD0);
                                                                         break;
                                                                case 0x9:cmd.itype=mn102_mulqh;
                                                                         SetImm(cmd.Op1,2);
                                                                         SetReg(cmd.Op2,R1+rD0);
                                                                         break;
                                                                default: return(0);
                                                                }
                                                        }
                                                        break;
                                        default:        return(0);
                                        }
                                        break;
                        // NOP
                        case 0x06:      cmd.itype=mn102_nop;
                                        break;
                        //набор F7
                        case 0x07:      code=ua_next_byte();
                                        R1=(code&3);
                                        R2=(code>>2)&3;
                                        switch ( code&0xF0 ){
                                        case 0x00:      {static const uchar Cmd[4]={
                                                        mn102_and,mn102_btst,mn102_add,mn102_sub};

                                                        SetImm(cmd.Op1,2);
                                                        SetReg(cmd.Op2,R1+((R2&2)?rA0:rD0));
                                                        cmd.itype=Cmd[R2];
                                                        }
                                                        break;

                                        case 0x10:      switch ( R2 ){
                                                        case 0: if ( R1!=0)return(0 );
                                                                cmd.itype=mn102_and;
                                                                SetReg(cmd.Op2,rPSW);
                                                                break;

                                                        case 1: if ( R1!=0)return(0 );
                                                                cmd.itype=mn102_or;
                                                                SetReg(cmd.Op2,rPSW);
                                                                break;

                                                        case 2: cmd.itype=mn102_add;
                                                                SetReg(cmd.Op2,R1+rD0);
                                                                break;

                                                        case 3: cmd.itype=mn102_sub;
                                                                SetReg(cmd.Op2,R1+rD0);
                                                                break;
                                                        }
                                                        SetImm(cmd.Op1,2);
                                                        break;

                                        case 0x20:      if ( R2!=0)return(0 );
                                                        cmd.itype=mn102_mov;
                                                        SetReg(cmd.Op1,R1+rA0);
                                                        SetMem(cmd.Op2,2,dt_tbyte);
                                                        break;

                                        case 0x30:      if ( R2!=0)return(0 );
                                                        cmd.itype=mn102_mov;
                                                        SetReg(cmd.Op2,R1+rA0);
                                                        SetMem(cmd.Op1,2,dt_tbyte);
                                                        break;

                                        case 0x40:      {static const uchar Cmd[4]={
                                                        mn102_or,0,mn102_cmp,mn102_xor};
                                                        if ( (cmd.itype=Cmd[R2])==0)return(0 );
                                                        SetImm(cmd.Op1,2);
                                                        SetReg(cmd.Op2,R1+rD0);
                                                        }
                                                        break;

                                        case 0x50:      cmd.itype=mn102_movbu;
                                                        SetDispl(cmd.Op1,R2+rA0,2);
                                                        SetReg(cmd.Op2,R1+rD0);
                                                        break;

                                        case 0x60:      cmd.itype=mn102_movx;
                                                        SetDispl(cmd.Op2,R2+rA0,2);
                                                        SetReg(cmd.Op1,R1+rD0);
                                                        break;


                                        case 0x70:      cmd.itype=mn102_movx;
                                                        SetDispl(cmd.Op1,R2+rA0,2);
                                                        SetReg(cmd.Op2,R1+rD0);
                                                        break;

                                        case 0x80:      cmd.itype=mn102_mov;
                                                        SetDispl(cmd.Op2,R2+rA0,2);
                                                        SetReg(cmd.Op1,R1+rD0);
                                                        break;

                                        case 0x90:      cmd.itype=mn102_movb;
                                                        SetDispl(cmd.Op2,R2+rA0,2);
                                                        SetReg(cmd.Op1,R1+rD0);
                                                        break;

                                        case 0xA0:      cmd.itype=mn102_mov;
                                                        SetDispl(cmd.Op2,R2+rA0,2);
                                                        SetReg(cmd.Op1,R1+rA0);
                                                        break;

                                        case 0xB0:      cmd.itype=mn102_mov;
                                                        SetDispl(cmd.Op1,R2+rA0,2);
                                                        SetReg(cmd.Op2,R1+rA0);
                                                        break;


                                        case 0xC0:      cmd.itype=mn102_mov;
                                                        SetDispl(cmd.Op1,R2+rA0,2);
                                                        SetReg(cmd.Op2,R1+rD0);
                                                        break;

                                        case 0xD0:      cmd.itype=mn102_mov;
                                                        SetDispl(cmd.Op1,R2+rA0,2);
                                                        SetReg(cmd.Op2,R1+rD0);
                                                        break;

                                        default:        return(0);
                                        }
                                        break;

                        // mov imm16, Dn
                        case 0x08:
                        case 0x09:
                        case 0x0A:
                        case 0x0B:      SetReg(cmd.Op2,R1+rD0);
                                        SetImm(cmd.Op1, 2);
                                        cmd.itype=mn102_mov;
                                        break;

                        // jmp label16
                        case 0x0C:      cmd.itype=mn102_jmp;
                                        SetLabel(cmd.Op1,2);
                                        break;

                        // jsr label16
                        case 0x0D:      cmd.itype=mn102_jsr;
                                        SetLabel(cmd.Op1,2);
                                        break;

                        // rts
                        case 0x0E:      cmd.itype=mn102_rts;
                                        break;

                        // illegal code
                        case 0x0F:      return(0);
                        }
                        break;
        }
return(cmd.size);
}
