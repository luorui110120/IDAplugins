/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "78k_0s.hpp"
#include <ints.hpp>

static bool flow;
//------------------------------------------------------------------------
// Конвертирование в данные(указан адресс) по указанному типу,
// добавить крос референсы для текущей инструкции
void DataSet(op_t &x, ea_t EA, int isload)
{
// Конвертирование в данные(указан адресс) по указанному типу
ua_dodata2(x.offb, EA, x.dtyp);
//добавить крос референсы для текущей инструкции
ua_add_dref(x.offb, EA, isload ? dr_R : dr_W);
}
//----------------------------------------------------------------------
static void TouchArg(op_t &x,int isAlt,int isload)
{
switch ( x.type )
  {
  case o_phrase:
    //Добавляем в список ошибок(выводим сообщение)
    //ошибку и адресс где это случилось
    //QueueMark(Q_jumps, cmd.ea);
  case o_void:
  case o_reg:
    break;

  case o_imm:
    {
    //Установить для данного байта признак immedia
    doImmd(cmd.ea);
    //Получить флаг для указанного линейного адресса
    if ( !isAlt )
      {
      uint32 offb;
      ushort addr = ushort(x.addr);
      if ( x.type == o_displ  )
        {
        addr += (ushort)cmd.ip;
        addr += cmd.size;
        //Получить линейный адресс
        offb = (uint32)toEA(codeSeg(addr,x.n), 0);
        DataSet(x, offb+addr, isload);
        }
      else if ( isOff(uFlag, x.n) )
        {
reref:
        ua_add_off_drefs(x, dr_O);
        if ( x.type == o_displ )
        //Преобразовать данные по указанному линейному адрессу в указанный тип
        ua_dodata2(x.offb, calc_target(cmd.ea+x.offb, cmd.ea, x.n, x.addr), x.dtyp);
        }
      else if ( x.type == o_displ && !x.reg && !isDefArg(uFlag, x.n ) &&
                 set_offset(cmd.ea, x.n, toEA(cmd.cs,0))) goto reref;
      }
    } break;

  case o_bit:
  case o_mem:
    // Конвертирование в данные(указан адресс) по указанному типу,
    //добавить крос референсы для текущей инструкции
    DataSet(x, toEA(codeSeg(x.addr,x.n), x.addr), isload);
    break;

  case o_near:
    {
    //Получить линейный адресс
    ea_t ea = toEA(cmd.cs, x.addr);
    //Проверить является ли значение по указанному линейному адрессу - инструкцией
    int iscall = InstrIsSet(cmd.itype, CF_CALL);
    //добавить крос референсы для текущей инструкции
    ua_add_cref(x.offb, ea, iscall ? fl_CN : fl_JN);
    if ( iscall )  flow = func_does_return(ea);
    } break;

  default:
    warning("%a: %s,%d: bad optype %d", cmd.ea, cmd.get_canon_mnem(), x.n, x.type);
    break;
  }
}
//----------------------------------------------------------------------
int idaapi emu(void)
{
uint32 Feature = cmd.get_canon_feature();
flow = (Feature & CF_STOP) == 0;

int flag1 = is_forced_operand(cmd.ea, 0);
int flag2 = is_forced_operand(cmd.ea, 1);
int flag3 = is_forced_operand(cmd.ea, 2);

if ( Feature & CF_USE1) TouchArg(cmd.Op1, flag1, 1 );
if ( Feature & CF_USE2) TouchArg(cmd.Op2, flag2, 1 );
if ( Feature & CF_USE3) TouchArg(cmd.Op3, flag3, 1 );
if ( Feature & CF_JUMP) QueueMark(Q_jumps, cmd.ea );
if ( Feature & CF_CHG1) TouchArg(cmd.Op1, flag1, 0 );
if ( Feature & CF_CHG2) TouchArg(cmd.Op2, flag2, 0 );
if ( Feature & CF_CHG3) TouchArg(cmd.Op3, flag3, 0 );

if ( flow) ua_add_cref(0, cmd.ea + cmd.size, fl_F );

return(1);
}
//----------------------------------------------------------------------
