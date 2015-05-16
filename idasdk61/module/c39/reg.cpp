/*
 *      Rockwell C39 processor module for IDA Pro.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "c39.hpp"
#include <diskio.hpp>
#include <entry.hpp>
#include <srarea.hpp>

//--------------------------------------------------------------------------
// список регистров
static const char * RegNames[] =
{
        // нулевка
        "",
        // обычные регистры
        "A","X","Y",
        // псевдо-сегмнтные
        "cs","ds"
};

#if IDP_INTERFACE_VERSION > 37
static netnode helper;
char device[MAXSTR] = "";
static size_t numports;
static ioport_t *ports;

#include "../iocommon.cpp"

//----------------------------------------------------------------------
static int idaapi notify(processor_t::idp_notify msgid, ...)
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
      helper.create("$ C39");
    default:
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
                break;
  }
  va_end(va);
  return(1);
}
#else

//----------------------------------------------------------------------
// функция оповещения
static int notify(int msgnum,void *arg,...)
{ // Various messages:
  qnotused(arg);
  switch ( msgnum ) {
  // новый файл
  case IDP_NEWFILE:
      inf.mf = 0;                                       // MSB last
      inf.nametype = NM_SHORT;
      segment_t *sptr = get_first_seg();
      if ( sptr != NULL ) {
        if ( sptr->startEA-get_segm_base(sptr) == 0 ) {
          inf.beginEA = sptr->startEA;
          inf.startIP = 0;
        }
      }
      // основной сегмент - кодовый
      set_segm_class(get_first_seg(), "CODE");
      break;
    // создание нового сегмента
    case IDP_NEWSEG:    {
                        segment_t *seg;
                        seg=((segment_t *)arg);
                        // установим регистры по умолчанию
                        seg->defsr[rVds-ph.regFirstSreg] = 0;
                        break;
                        }
  }
  return 1;
}
#endif
//-----------------------------------------------------------------------
//      Checkarg data. Common for all assemblers. Not good.
//-----------------------------------------------------------------------
static const char *operdim[15] = {  // ВСЕГДА И СТРОГО 15
     "(", ")", "!", "-", "+", "%",
     "\\", "/", "*", "&", "|", "^", "<<", ">>", NULL};
//-----------------------------------------------------------------------
//      PseudoSam
//-----------------------------------------------------------------------
static asm_t pseudosam = {
  AS_COLON | AS_UDATA | ASH_HEXF3 | ASD_DECF0,
  // пользовательские флажки
  0,
  "Generic C39 assembler",              // название ассемблера
  0,                                    // номер в help'e
  NULL,                                 // автозаголовок
  NULL,                                 // массив не испоьзующихся инструкций
  "org",                                // Директива ORG
  "end",                                // Директива end

  ";",                                  // коментарий
  '"',                                  // разделитель строки
  '\'',                                 // символьная константа
  "\\\"'",                              // спецсимволы

  "db",                                 // ascii string directive
  ".DATA.B",                             // byte directive
  ".DATA.W",                             // word directive
  ".DATA.L",                             // dword  (4 bytes)
  NULL,                                 // qword  (8 bytes)
#if IDP_INTERFACE_VERSION > 37
  NULL,     // oword  (16 bytes)
#endif
  NULL,                                 // float  (4 bytes)
  NULL,                                 // double (8 bytes)
  NULL,                                 // tbyte  (10/12 bytes)
  NULL,                                 // packed decimal real
  "#d dup(#v)",                         // arrays (#h,#d,#v,#s(...)
  "db ?",                               // uninited arrays
  ".equ",                               // equ
  NULL,                                 // seg prefix
  NULL,                              // контроль
  NULL,                                 // atomprefix
  operdim,                              // массив операций
  NULL,                                 // перекодировка в ASCII
  "$",                                  // Текущий IP
  NULL,                                 // Заголовок функции
  NULL,                                 // Конец функции
  NULL,                                 // директива public
  NULL,                                 // директива weak
  NULL,                                 // директива extrn
  NULL,                                 // директива comm
  NULL,                                 // получить имя типа
  ".ALIGN"                              // ключ align
#if IDP_INTERFACE_VERSION > 37
  ,'(', ')',     // lbrace, rbrace
  NULL,    // mod
  NULL,    // and
  NULL,    // or
  NULL,    // xor
  NULL,    // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
#endif
};

// Список ассемблеров
static asm_t *asms[] = { &pseudosam, NULL };
//-----------------------------------------------------------------------
// короткие имена процессоров
static const char *shnames[] = { "C39", NULL };
// длинные имена процессоров
static const char *lnames[] = { "C39", NULL };

//--------------------------------------------------------------------------
// коды возвратов из п/п
static uchar retcode_1[] = { 0x00, 0x0B };    // RTS
static bytes_t retcodes[] = {
 { sizeof(retcode_1), retcode_1 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH = {
  IDP_INTERFACE_VERSION,        // version
  PLFM_C39,                     // id процессора
#if IDP_INTERFACE_VERSION > 37
  PR_USE32|PR_BINMEM|PR_SEGTRANS,      // can use register names for byte names
  8,                                                    // 8 bits in a byte for code segments
#else
  PR_USE32,         // can use register names for byte names
#endif
  8,                            // 8 bits in a byte

  shnames,                      // короткие имена процессоров (до 9 символов)
  lnames,                       // длинные имена процессоров

  asms,                         // список компиляторов

  notify,                       // функция оповещения

  C39_header,                   // создание заголовка текста
  C39_footer,                   // создание конца текста

  C39_segstart,                 // начало сегмента
  std_gen_segm_footer,          // конец сегмента - стандартный, без завершения

  NULL,                         // директивы смены сегмента - не используются

  C39_ana,                      // канализатор
  C39_emu,                      // эмулятор инструкций

  C39_out,                      // текстогенератор
  C39_outop,                    // тектогенератор операндов
  C39_data,                     // генератор описания данных
  NULL,                         // сравнивалка операндов
  NULL,                         // can have type

  qnumber(RegNames),            // Number of registers
  RegNames,                     // Regsiter names
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
  0,C39_last,                   // первая и последняя инструкции
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
#if IDP_INTERFACE_VERSION > 37
  NULL,                                                 // Get size of function return address in bytes (2/4 by default)
#endif
  NULL,                         // создание строки описания стековой переменной
  NULL,                         // генератор текста для ....
  0,                            // Icode для команды возврата
  NULL,                         // передача опций в IDP
  NULL,                                                 // Is the instruction created only for alignment purposes?
  NULL                          // micro virtual mashine
#if IDP_INTERFACE_VERSION > 37
  ,0                                                    // fixup bit's
#endif
};
