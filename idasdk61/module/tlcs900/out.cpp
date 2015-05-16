/*
 *      TLCS900 processor module for IDA Pro.
 *      Copyright (c) 1998-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "tosh.hpp"

// фразы
static const char *phrases[] = {
        // нулевка
        "",
        // условия
        "F", "LT", "LE", "ULE", "PE", "MI", "Z", "C" ,
        "(T)", "GE", "GT", "UGT", "PO", "PL", "NZ", "NC",
        // спецрегистр
        "F","F'",
        // прочее
        "SR","PC"
        };


// варианты названий регистров
static const unsigned char reg_byte[8]=
{  rW,   rA,   rB,   rC,   rD,   rE,   rH,   rL};
static const unsigned char reg_word[8]=
{ rWA,  rBC,  rDE,  rHL,  rIX,  rIY,  rIZ,  rSP};
static const unsigned char reg_long[8]=
{rXWA, rXBC, rXDE, rXHL, rXIX, rXIY, rXIZ, rXSP};
static const unsigned char reg_ib[8]=
{rIXL, rIXH, rIYL, rIYH, rIZL, rIZH, rSPL, rSPH};

//----------------------------------------------------------------------
// вывести название регистра
static inline void OutReg(size_t rgnum, uchar size)
{
ushort reg_name=0;      // код основной фразы регистра
if ( size!=dt_dword ){
        // если 32 - без префиксов!
        if ( rgnum&2 ){ // префикс Q
                out_symbol('Q');
        }
        else{ //м.б. нужен R ?
                if ( rgnum<0xD0) out_symbol('R' );
        }
}
// выдадим само название регистра
switch ( size ){
case dt_byte:   if ( (rgnum&0xF0)!=0xF0 ){
                        // обычные регистры
                        reg_name=reg_byte[((1-rgnum)&1)|((rgnum>>1)&6)];
                }
                else { // байтовый I*- регистры
                        reg_name=reg_ib[(rgnum&1)|((rgnum>>1)&6)];
                }
                break;
case dt_word:   if ( (rgnum&0xF0)!=0xF0 ){
                        // это основные словные регистры
                        reg_name=reg_word[(rgnum>>2)&3];
                }
                else {
                        // старшие регистры
                        reg_name=reg_word[((rgnum>>2)&3)+4];
                }
                break;
case dt_dword:  if ( (rgnum&0xF0)!=0xF0 ){
                        // это основные словные регистры
                        reg_name=reg_long[(rgnum>>2)&3];
                }
                else {
                        // старшие регистры
                        reg_name=reg_long[((rgnum>>2)&3)+4];
                }
                break;
// спецрегистры
case 255:       reg_name=ushort(rgnum);
                break;
}
if ( reg_name>=ph.regsNum ){
        out_symbol('?');
        msg("Bad Register Ref=%x, size=%x\n",(int)reg_name,(int)size);
}
else out_register(ph.regNames[reg_name]);
// выдадим постфикс регистра
if ( (rgnum&0xF0)==0xD0)out_symbol('\'' );   // апостроф
// или название банка
else if ( rgnum<0xD0)out_symbol('0'+((rgnum>>4)&0xF) );
}

// получить имя метки
static void OutVarName(op_t &x)
{
ea_t addr = x.addr;
ea_t toea = toEA(codeSeg(addr,x.n), addr);
#if IDP_INTERFACE_VERSION > 37
//      msg("AT:%a target=%lx, segm=%lx, Result=%lx\n",
//                      cmd.ea,addr, codeSeg(addr,x.n),toea);
        if ( out_name_expr(x,toea,addr) )return;
#else
        const char *ptr;
        if ( (ptr=get_name_expr(cmd.ea+x.offb, toea, addr)) != NULL ){
                //вывод имен переменных и меток перехода
            OutLine(ptr);
        }
#endif
        else{
                OutValue(x, OOF_ADDR | OOF_NUMBER |
                                        OOFS_NOSIGN | OOFW_32);
                // пометим проблему - нет имени
                QueueMark(Q_noName,cmd.ea);
        }
}

//----------------------------------------------------------------------
// вывод одного операнда
bool idaapi T900_outop(op_t &x)
{
  switch ( x.type ){
  // только регистр,  без специфики, но с кодами
  case o_reg:           OutReg((size_t)x.value,x.dtyp);
                        break;

  // фраза
  case o_phrase:        OutLine(phrases[x.phrase]);
                        break;

  // непосредственные данные
  case o_imm:
  ImmOut:
#if IDP_INTERFACE_VERSION > 37
                                refinfo_t ri;
                                // micro bug-fix
                                if ( get_refinfo(cmd.ea, x.n, &ri) ){
                                        if ( ri.flags==REF_OFF16 )
                                                set_refinfo(cmd.ea, x.n,
                                                        REF_OFF32, ri.target, ri.base, ri.tdelta);
                        msg("Exec OFF16_Op Fix AT:%a Flags=%x, Target=%a, Base=%a, Delta=%a\n",
                                cmd.ea,
                                ri.flags,ri.target,ri.base,ri.tdelta);
                                }
#endif
                                                OutValue(x, OOFS_NOSIGN | OOFW_IMM);
                        break;

  // прямая ссылка на память или программу
  case o_mem:
  case o_near:
                if ( x.specflag1&URB_LDA2 ){
                        if ( isDefArg1(getFlags(cmd.ea)) )goto ImmOut;
                }
                if ( !(x.specflag1&URB_LDA))out_symbol('(' );
                // получим имя, если оно есть
                                OutVarName(x);
                if ( !(x.specflag1&URB_LDA))out_symbol(')' );
                break;

  // ссылка на память с использованием регистра (регистров)
  case o_displ: // открывающая скобка есть всегда
                if ( !(x.specflag1&URB_LDA))out_symbol('(' );
                // регистр пристуствует?
                if ( x.reg!=rNULLReg ){
                        // если это декремент - поставим минус
                        if ( x.specflag2&URB_DECR)out_symbol('-' );
                        // выведем основной регистр
                        OutReg(x.reg,2);        // размер всегда 32 бита
                        // есть декремент ?
                        if ( x.specflag2&URB_DCMASK ){
                                if ( (x.specflag2&URB_DECR)==0)out_symbol('+' );
                                out_symbol(':');
                                out_symbol('0'+(x.specflag2&7));
                        }
                        // обработка одиночных декреметов
                        if ( x.specflag2&URB_UDEC)out_symbol('-' );
                        if ( x.specflag2&URB_UINC)out_symbol('+' );
                        // смещение есть ?
                        if ( x.offb!=0 ){
                                out_symbol('+');
                                // если смещение - выведем смещением
                                                                if ( isOff(uFlag,x.n) ){
                                                                        OutVarName(x);
                                                                }
                                                                else OutValue(x,OOF_ADDR | OOF_NUMBER |
                                                OOFS_NOSIGN | OOFW_32);
                        }
                        // дополнительный регистр есть?
                        if ( x.specval_shorts.low!=rNULLReg ){
                                out_symbol('+');
                                OutReg( x.specval_shorts.low,
                                        x.specflag1&URB_WORD?dt_word:dt_byte);
                        }
                }
                // закрывающая скобка тоже есть всегда
                if ( !(x.specflag1&URB_LDA))out_symbol(')' );
                break;

  // пустыка не выводится
  case o_void:  return 0;
  // неизвестный операнд
  default:      warning("out: %a: bad optype %d", cmd.ea, x.type);
                break;
  }
  return 1;
}

//----------------------------------------------------------------------
// основная выводилка команд
void idaapi T900_out(void)
{
  char buf[MAXSTR];
#if IDP_INTERFACE_VERSION > 37
   init_output_buffer(buf, sizeof(buf)); // setup the output pointer
#else
   u_line = buf;
#endif
  // выведем мнемонику
  OutMnem();

  // выведем первый операнд
  if ( cmd.Op1.type!=o_void)out_one_operand(0 );

  // выведем второй операнд
  if ( cmd.Op2.type != o_void ){
        out_symbol(',');
        OutChar(' ');
        out_one_operand(1);
  }

  // выведем непосредственные данные, если они есть
  if ( isVoid(cmd.ea,uFlag,0) ) OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea,uFlag,1) ) OutImmChar(cmd.Op2);

  // завершим строку
#if IDP_INTERFACE_VERSION > 37
   term_output_buffer();
#else
  *u_line = '\0';
#endif
  gl_comm = 1;
  MakeLine(buf);
}

//--------------------------------------------------------------------------
// заголовок текста листинго
void idaapi T900_header(void)
{
#if IDP_INTERFACE_VERSION > 37
  gen_cmt_line("Processor:       %s [%s]", device[0] ? device : inf.procName, deviceparams);
#else
  gen_cmt_line("Processor:       %s", inf.procName);
#endif
  gen_cmt_line("Target assembler: %s", ash.name);
  // заголовок для конкретного ассемблера
  if ( ash.header != NULL )
    for ( const char **ptr=ash.header; *ptr != NULL; ptr++ ) MakeLine(*ptr,0);
}

//--------------------------------------------------------------------------
// начало сегмента
void idaapi T900_segstart(ea_t ea)
{
  segment_t *Sarea = getseg(ea);
  const char *SegType=  (Sarea->type==SEG_CODE)?"CSEG":
                                                ((Sarea->type==SEG_DATA)?"DSEG":
                                                "RSEG"
                                                );
        // Выведем строку вида RSEG <NAME>
#if IDP_INTERFACE_VERSION > 37
        char sn[MAXNAMELEN];
        get_segm_name(Sarea,sn,sizeof(sn));
        printf_line(-1,"%s %s ",SegType, sn);
#else
        printf_line(-1,"%s %s ",SegType, get_segm_name(Sarea));
#endif
        // если смещение не ноль - выведем и его (ORG XXXX)
        if ( inf.s_org ) {
                ea_t org = ea - get_segm_base(Sarea);
                if( org != 0 ){
#if IDP_INTERFACE_VERSION > 37
                        char bufn[MAX_NUMBUF];
                        btoa(bufn, sizeof(bufn), org);
                        printf_line(-1, "%s %s", ash.origin, bufn);
#else
                        printf_line(-1, "%s %s", ash.origin, btoa(org));
#endif
                }
        }
}

//--------------------------------------------------------------------------
// конец текста
void idaapi T900_footer(void)
{
  char buf[MAXSTR];
  char *const end = buf + sizeof(buf);
  if ( ash.end != NULL ) {
    MakeNull();
#if IDP_INTERFACE_VERSION > 37
    char *ptr = tag_addstr(buf, end, COLOR_ASMDIR, ash.end);
    char name[MAXSTR];
    if ( get_colored_name(BADADDR, inf.beginEA, name, sizeof(name)) != NULL ){
    register size_t i = strlen(ash.end);
                do APPCHAR(ptr, end, ' '); while ( ++i < 8 );
                APPEND(ptr, end, name);
    }
    MakeLine(buf,inf.indent);

#else
    register char *p = tag_addstr(buf, COLOR_ASMDIR, ash.end);
    const char *start = get_colored_name(inf.beginEA);
    if ( start != NULL ) {
      *p++ = ' ';
      strcpy(p, start);
    }
    MakeLine(buf);
#endif
  } else gen_cmt_line("end of file");
}

//--------------------------------------------------------------------------
void idaapi T900_data(ea_t ea)
{
#if IDP_INTERFACE_VERSION > 37
refinfo_t ri;
        // micro bug-fix
        if ( get_refinfo(ea, 0, &ri) ){
                if ( ri.flags==REF_OFF16 ){
                        set_refinfo(ea, 0,
                                REF_OFF32, ri.target, ri.base, ri.tdelta);
                msg("Exec OFF16 Fix AT:%a Flags=%x, Target=%a, Base=%a, Delta=%a\n",ea,
                                ri.flags,ri.target,ri.base,ri.tdelta);
                }
        }
#endif
        gl_name = 1;
        intel_data(ea);
}
