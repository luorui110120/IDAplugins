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
#include <diskio.hpp>

//----------------------------------------------------------------------
inline void OutReg(int rgnum)
{
out_register(ph.regNames[rgnum]);
}
//----------------------------------------------------------------------
static int OutVarName(op_t &x, int iscode, int relative)
{
//char *ptr;
ushort addr = ushort(x.addr);
if ( relative )
  {
  addr += (ushort)cmd.ip;
  addr += cmd.size;           // ig: this is tested only for 6809
  }
//Получить линейный адресс
ea_t toea = toEA((iscode || relative) ? codeSeg(addr,x.n) : dataSeg_op(x.n), addr);
//Получть строку для данного лин. адресса
return out_name_expr(x, toea, addr);
}
//----------------------------------------------------------------------
bool idaapi outop(op_t &x)
{
switch ( x.type )
  {
  case o_void:  return 0;

  case o_reg:
    if ( x.prepost) out_symbol('[' );
    //Вывод регистра по номеру в регистре
    OutReg(x.reg);
    if ( x.xmode )
      {
      out_symbol('+');
      OutValue(x, OOF_ADDR | OOF_NUMBER | OOFW_8);
      }
    if ( x.prepost) out_symbol(']' );
    break;

  case o_phrase:
    OutLine(ph.regNames[x.reg]);
    break;

  case o_bit:
    {
    switch ( x.reg )
      {
      case rPSW:
        {
        OutLine("PSW.");
        switch ( x.value )
          {
          case 0: OutLine("CY");break;
          case 4: OutLine("AC");break;
          case 6: OutLine("Z");break;
          case 7: OutLine("IE");break;
          default:OutValue(x, OOFW_IMM);
          } break;
        }

      case rA:
        {
        OutLine( "A." );
        OutChar(char('0'+x.value));
        } break;

      default:
        {
        if ( !OutVarName(x, 1, 0) ) OutValue(x, OOF_ADDR | OOFW_16 );
        out_symbol('.');
        //Ичем название бита по указанному адрессу
        if ( !nec_find_ioport_bit((int)x.addr, (int)x.value) )
          {
          //Вывод данных(тип o_imm)
          OutChar(char('0'+x.value));
          }
        }//       switch ( x.regmode )
      }  // end switch ( x.reg )
    } break;

  case o_imm:
    {
    if ( !x.regmode )
      {
      out_symbol('#');
      //Вывод данных(тип o_imm)
      OutValue(x, OOFW_IMM );
      }
    else
      {
      out_symbol('1');
      }
    } break;

  case o_mem:
    {
    if ( x.addr16) out_symbol('!' );
    //выводит имя переменной из памяти(например byte_98)
    //Вывод имени переменной
    if ( !OutVarName(x, 1, 0)  )
    //Вывод данных
    OutValue(x, OOF_ADDR | OOFW_16);
    } break;

  case o_near:
    {
    if ( x.addr16) out_symbol('!' );
    if ( x.form) out_symbol('[' );
    //Получить линейный адресс
    ea_t v = toEA(cmd.cs,x.addr);
    if ( !out_name_expr(x, v, x.addr) )
      {
      //Вывести значение
      OutValue(x, OOF_ADDR | OOF_NUMBER | OOFW_16);
      QueueMark(Q_noName, cmd.ea);
      }
    if ( x.form) out_symbol(']' );
    } break;

  default:
    warning("out: %a: bad optype %d", cmd.ip, x.type);
    break;
  }

return(1);
}
//----------------------------------------------------------------------
void idaapi out(void)
{
char buf[MAXSTR];

init_output_buffer(buf, sizeof(buf)); // setup the output pointer
OutMnem();                            // output instruction mnemonics

out_one_operand(0);                   // output the first operand

//Вывод операнда
if ( cmd.Op2.type != o_void )
  {
  out_symbol(',');//вывод разделителя между операндами
  //если неуказан флаг UAS_NOSPA ставим пробел
  if ( !(ash.uflag & UAS_NOSPA)) OutChar(' ' );
  out_one_operand(1);
  }

if ( cmd.Op3.type != o_void )
  {
  out_symbol(',');
  if ( !(ash.uflag & UAS_NOSPA)) OutChar(' ' );
  out_one_operand(2);
  }

if ( isVoid(cmd.ea, uFlag, 0)) OutImmChar(cmd.Op1 );
if ( isVoid(cmd.ea, uFlag, 1)) OutImmChar(cmd.Op2 );
if ( isVoid(cmd.ea, uFlag, 2)) OutImmChar(cmd.Op3 );

term_output_buffer();

gl_comm = 1;
MakeLine(buf);
}
//--------------------------------------------------------------------------
void idaapi header(void)
{
gen_cmt_line("Processor:       %s [%s]", device[0] ? device : inf.procName, deviceparams);
gen_cmt_line("Target assebler: %s", ash.name);
if ( ash.header != NULL  )
for (const char **ptr=ash.header; *ptr != NULL; ptr++ ) MakeLine(*ptr, 0);
}
//--------------------------------------------------------------------------
void idaapi segstart(ea_t /*ea*/)
{
}
//--------------------------------------------------------------------------
void idaapi footer(void)
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
    register size_t i = strlen(ash.end);
    do APPCHAR(ptr, end, ' '); while ( ++i < 8 );
    APPEND(ptr, end, name);
    }
  MakeLine(buf, inf.indent);
  }
else gen_cmt_line("end of file");
}
//--------------------------------------------------------------------------
