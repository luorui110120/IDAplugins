/*
 *      NEC 78K0 processor module for IDA Pro.
 *      Copyright (c) 2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "78k0.hpp"
#include <diskio.hpp>
#include <entry.hpp>
#include <srarea.hpp>

//----------------------------------------------------------------------
static const char *RegNames[] = {
  "X", "A", "C", "B", "E", "D", "L", "H", "AX", "BC", "DE","HL",
  "PSW", "SP", "CY", "RB0", "RB1", "RB2", "RB3",
  "cs", "ds"
};

//----------------------------------------------------------------------
static asm_t nec78k0 = {
  AS_COLON | ASB_BINF4 | AS_N2CHR ,
  // пользовательские флажки
  0,
  "NEC 78K0 Assembler",                 // название ассемблера
  0,                                                    // номер в help'e
  NULL,                                                 // автозаголовок
  NULL,                                                 // массив не испоьзующихся инструкций
  ".org",
  ".end",

  ";",        // comment string
  '"',        // string delimiter
  '\'',       // char delimiter
  "'\"",      // special symbols in char and string constants

  ".db",    // ascii string directive
  ".db",    // byte directive
  ".dw",    // word directive
  ".dd",     // no double words
  NULL,     // no qwords
  NULL,     // oword  (16 bytes)
  NULL,     // no float
  NULL,     // no double
  NULL,     // no tbytes
  NULL,     // no packreal
  "#d dup(#v)",     //".db.#s(b,w) #d,#v",   // #h - header(.byte,.word)
                    // #d - size of array
                    // #v - value of array elements
                    // #s - size specifier
  ".rs %s",    // uninited data (reserve space)
  ".equ",
  NULL,         // seg prefix
  NULL,         // preline for checkarg
  NULL,      // checkarg_atomprefix
  NULL,   // checkarg operations
  NULL,   // XlatAsciiOutput
  "$",    // a_curip

  NULL,         // returns function header line
  NULL,         // returns function footer line
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL         // align

  ,'(', ')',     // lbrace, rbrace
  NULL,    // mod
  NULL,    // and
  NULL,    // or
  NULL,    // xor
  NULL,    // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
};


//----------------------------------------------------------------------
//----------------------------------------------------------------------
static const char *shnames[] =
{
  "78k0",
  NULL
};
static const char *lnames[] =
{
  "NEC 78K0",
  NULL
};

static asm_t *asms[] =
{
  &nec78k0,
  NULL
};

//--------------------------------------------------------------------------
static uchar retcNEC78K0_0[] = { 0xAF };    //ret
static uchar retcNEC78K0_1[] = { 0x9F };    //retb
static uchar retcNEC78K0_2[] = { 0x8F };    //reti
static uchar retcNEC78K0_3[] = { 0xBF };    //brk
static const bytes_t retcodes[] = {
 { sizeof(retcNEC78K0_0), retcNEC78K0_0 },
 { sizeof(retcNEC78K0_1), retcNEC78K0_1 },
 { sizeof(retcNEC78K0_2), retcNEC78K0_2 },
 { sizeof(retcNEC78K0_3), retcNEC78K0_3 },
 { 0, NULL }
};


//----------------------------------------------------------------------

static netnode helper;
char device[MAXSTR] = "";
static size_t numports;
static ioport_t *ports;

#include "../iocommon.cpp"


//------------------------------------------------------------------
bool nec_find_ioport_bit(int port, int bit)
{

  //поиск бита из регистра в списке портов
  const ioport_bit_t *b = find_ioport_bit(ports, numports, port, bit);
  if ( b != NULL && b->name != NULL ){
    //выводим имя бита из регистра
    out_line(b->name, COLOR_IMPNAME);
    return true;
  }
  return false;
}

//------------------------------------------------------------------
const char *set_idp_options(const char *keyword,int /*value_type*/,const void * /*value*/)
{
  if ( keyword != NULL ) return IDPOPT_BADKEY;
  //функция выбирает все процессора из указанного файла cfg
  //3 параметр это callbak функция, которая вызывается при обнпружении процессора
  char cfgfile[QMAXFILE];
  get_cfg_filename(cfgfile, sizeof(cfgfile));
  if ( choose_ioport_device(cfgfile, device, sizeof(device), parse_area_line0) )
    set_device_name(device, IORESP_PORT|IORESP_INT);
  return IDPOPT_OK;
}
//----------------------------------------------------------------------

void set_dopolnit_info(void)
{
   for(int NumBanck = 0; NumBanck < 4; NumBanck++)
     for(int Regs = 0; Regs < 8; Regs++){
      char temp[100];
      qsnprintf(temp, sizeof(temp), "Bank%d_%s", NumBanck, RegNames[Regs]);
      //Вычисляем адресс
      ushort Addr = ushort(0xFEE0+((NumBanck*8)+Regs));
      //Устанавливаем имя порта
      set_name(Addr, temp);
      //Устанавливаем коментарий
      qsnprintf(temp, sizeof(temp), "Internal high-speed RAM (Bank %d registr %s)", NumBanck, RegNames[Regs]);
      set_cmt(Addr, temp, true);
     }
}

//----------------------------------------------------------------------
static int notify(processor_t::idp_notify msgid, ...)
{
  va_list va;
  va_start(va, msgid);
// A well behaving processor module should call invoke_callbacks()
// in his notify() function. If this function returns 0, then
// the processor module should process the notification itself
// Otherwise the code should be returned to the caller:

  int code = invoke_callbacks(HT_IDP, msgid, va);
  if ( code ) return code;

  switch ( msgid ){
    case processor_t::init:
      inf.mf = 0;
      inf.s_genflags |= INFFL_LZERO;
      helper.create("$ 78k0");
      break;

    case processor_t::term:
      free_ioports(ports, numports);
      break;

    case processor_t::newfile:
      //Выводит длг. окно процессоров, и позволяет выбрать нужный, считывает для выбраного
      //процессора информацию из cfg. По считаной информации подписывает порты и регстры
      {
        char cfgfile[QMAXFILE];
        get_cfg_filename(cfgfile, sizeof(cfgfile));
                if ( choose_ioport_device(cfgfile, device, sizeof(device), parse_area_line0) )
          set_device_name(device, IORESP_ALL);
        set_dopolnit_info();
      }
      break;

    case processor_t::newprc:{
          char buf[MAXSTR];
          if ( helper.supval(-1, buf, sizeof(buf)) > 0 )
            set_device_name(buf, IORESP_PORT);
        }
        break;

    case processor_t::newseg:{
                segment_t *s = va_arg(va, segment_t *);
                // Set default value of DS register for all segments
                set_default_dataseg(s->sel);
                }
    default:
                break;
  }
  va_end(va);
  return(1);
}

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  0x8078,                       // id процессора
  PRN_HEX|PR_SEGTRANS|PR_SEGS,  // can use register names for byte names
  8,                                                    // 8 bits in a byte for code segments
  8,                            // 8 bits in a byte

  shnames,                      // короткие имена процессоров (до 9 символов)
  lnames,                       // длинные имена процессоров

  asms,                         // список компиляторов

  notify,                       // функция оповещения

  N78K_header,                  // создание заголовка текста
  N78K_footer,                  // создание конца текста

  N78K_segstart,                // начало сегмента
  std_gen_segm_footer,          // конец сегмента - стандартный, без завершения

  NULL,                         // директивы смены сегмента - не используются

  N78K_ana,                     // канализатор
  N78K_emu,                     // эмулятор инструкций

  N78K_out,                     // текстогенератор
  N78K_outop,                   // тектогенератор операндов
  N78K_data,                    // генератор описания данных
  NULL,                         // сравнивалка операндов
  NULL,                         // can have type

  qnumber(RegNames),            // Number of registers
  RegNames,                                             // Regsiter names
  NULL,                         // получить значение регистра

  0,                            // число регистровых файлов
  NULL,                         // имена регистровых файлов
  NULL,                         // описание регистров
  NULL,                         // Pointer to CPU registers
  rVcs,rVds,
#if IDP_INTERFACE_VERSION > 37
  2,                            // size of a segment register
#endif
  rVcs,rVds,
  NULL,                         // типичные коды начала кодов
  retcodes,                     // коды return'ov
#if IDP_INTERFACE_VERSION <= 37
  NULL,                         // возвращает вероятность кодовой последовательности
#endif
  0,NEC_78K_0_last,                             // первая и последняя инструкции
  Instructions,                 // массив названия инструкций
  NULL,                         // проверка на инструкцию дальнего перехода
#if IDP_INTERFACE_VERSION <= 37
  NULL,                         // встроенный загрузчик
#endif
  NULL,                         // транслятор смещений
  3,                            // размер tbyte - 24 бита
  NULL,                         // преобразователь плавающей точки
  {0,0,0,0},                    // длины данных с плавающей точкой
  NULL,                         // поиск switch
  NULL,                         // генератор MAP-файла
  NULL,                         // строка -> адрес
  NULL,                         // проверка на смещение в стеке
  NULL,                         // создание фрейма функции
  NULL,                                                 // Get size of function return address in bytes (2/4 by default)
  NULL,                         // создание строки описания стековой переменной
  NULL,                         // генератор текста для ....
  0,                            // Icode для команды возврата
  NULL,                         // передача опций в IDP
  NULL,                                                 // Is the instruction created only for alignment purposes?
  NULL,                         // micro virtual mashine
  0                                                     // fixup bit's
};
