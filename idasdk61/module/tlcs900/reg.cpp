/*
 *      TLCS900 processor module for IDA Pro.
 *      Copyright (c) 1998-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "tosh.hpp"
#include <diskio.hpp>
#include <entry.hpp>
#include <srarea.hpp>

//--------------------------------------------------------------------------
// список регистров
static const char *RegNames[] =
{
        // нулевка
        "",
        // байтовые регистры
        "W","A","B","C","D","E","H","L",
        // словные регистры
        "WA","BC","DE","HL","IX","IY","IZ","SP",
        // двойное слово
        "XWA","XBC","XDE","XHL","XIX","XIY","XIZ","XSP",
        // дурные
        "IXL","IXH","IYL","IYH","IZL","IZH","SPL","SPH",
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
      helper.create("$ TLCS900");
      break;

    case processor_t::term:
      free_ioports(ports, numports);
    default:
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
// описание предопределенных адресов
typedef struct {
  uchar addr;   // адрес
  char *name;   // имя
  char *cmt;    // коментарий
} predefined_t;


//----------------------------------------------------------------------
// внутренние регистры процессора
static const predefined_t iregs[] = {
  { 0x00, "P0",         "Port 0" },
  { 0x01, "P1",         "Port 1" },
  { 0x02, "P0CR",       "Port 0 Control" },
  { 0x04, "P1CR",       "Port 1 Control" },
  { 0x05, "P1FC",       "Port 1 Function"},
  { 0x06, "P2",         "Port 2"},
  { 0x07, "P3",         "Port 3"},
  { 0x08, "P2CR",       "Port 2 Control"},
  { 0x09, "P2FC",       "Port 2 Function"},
  { 0x0A, "P3CR",       "Port 3 Control"},
  { 0x0B, "P3FC",       "Port 3 Function"},
  { 0x0C, "P4",         "Port 4"},
  { 0x0D, "P5",         "Port 5"},
  { 0x0E, "P4CR",       "Port 4 Control"},
  { 0x10, "P4FC",       "Port 4 Function"},
  { 0x12, "P6",         "Port 6"},
  { 0x13, "P7",         "Port 7"},
  { 0x14, "P6CR",       "Port 6 Control"},
  { 0x15, "P7CR",       "Port 7 Control"},
  { 0x16, "P6FC",       "Port 6 Function"},
  { 0x17, "P7FC",       "Port 7 Function"},
  { 0x18, "P8",         "Port 8"},
  { 0x19, "P9",         "Port 9"},
  { 0x1A, "P8CR",       "Port 8 Control"},
  { 0x1B, "P9CR",       "Port 9 Control"},
  { 0x1C, "P8FC",       "Port 8 Function"},
  { 0x1D, "P9FC",       "Port 9 Function"},
  { 0x1E, "PA",         "Port A"},
  { 0x1F, "PACR",       "Port A Control"},
  { 0x20, "TRUN",       "Timer Control"},
  { 0x22, "TREG0",      "Timer Register 0"},
  { 0x23, "TREG1",      "Timer Register 1"},
  { 0x24, "TMOD",       "Timer Source CLK & MODE"},
  { 0x25, "TFFCR",      "Flip-Flop Control"},
  { 0x26, "TREG2",      "Timer Register 2"},
  { 0x27, "TREG3",      "Timer Register 3"},
  { 0x28, "P0MOD",      "PWM0 Mode"},
  { 0x29, "P1MOD",      "PWM1 Mode"},
  { 0x2A, "PFFCR",      "PWM Flip-Flop Control"},
  { 0x30, "TREG4L",     "Timer Register 4 Low"},
  { 0x31, "TREG4H",     "Timer Register 4 High"},
  { 0x32, "TREG5L",     "Timer Register 5 Low"},
  { 0x33, "TREG5H",     "Timer Register 5 High"},
  { 0x34, "CAP1L",      "Capture Register 1 Low"},
  { 0x35, "CAP1H",      "Capture Register 1 High"},
  { 0x36, "CAP2L",      "Capture Register 2 Low"},
  { 0x37, "CAP2H",      "Capture Register 2 High"},
  { 0x38, "T4MOD",      "Timer 4 Source CLK & Mode"},
  { 0x39, "T4FFCR",     "Timer 4 Flip-Flop Control"},
  { 0x3A, "T45CR",      "T4, T5 Control"},
  { 0x40, "TREG6L",     "Timer Register 6 Low"},
  { 0x41, "TREG6H",     "Timer Register 6 High"},
  { 0x42, "TREG7L",     "Timer Register 7 Low"},
  { 0x43, "TREG7H",     "Timer Register 7 High"},
  { 0x44, "CAP3L",      "Capture Register 3 Low"},
  { 0x45, "CAP3H",      "Capture REgister 3 High"},
  { 0x46, "CAP4L",      "Capture Register 4 Low"},
  { 0x47, "CAP4H",      "Capture Register 4 High"},
  { 0x48, "T5MOD",      "Timer 5 Source CLK & Mode"},
  { 0x49, "T5FFCR",     "Timer 5 Flip-Flip Control"},
  { 0x50, "SC0BUF",     "Serial Chanel 0 Buffer"},
  { 0x51, "SC0CR",      "Serial Chanel 0 Control"},
  { 0x52, "SC0MOD",     "Serial Chanel 0 Mode"},
  { 0x53, "BR0CR",      "Serial Chanel 0 Baud Rate"},
  { 0x54, "SC1BUF",     "Serial Chanel 1 Buffer"},
  { 0x55, "SC1CR",      "Serial Chanel 1 Control"},
  { 0x56, "SC1MOD",     "Serial Chanel 1 Mode"},
  { 0x57, "BR1CR",      "Serial Chanel 1 Baud Rate"},
  { 0x58, "ODE",        "Serial Open Drain Enable"},
  { 0x5C, "WDMOD",      "Watch Dog Timer Mode"},
  { 0x5D, "WDCR",       "Watch Dog Control Register"},
  { 0x5E, "ADMOD1",     "A/D Mode Register 1"},
  { 0x5F, "ADMOD2",     "A/D Mode Register 2"},
  { 0x60, "ADREG04L",   "A/D Result Register 0/4 Low"},
  { 0x61, "ADREG04H",   "A/D Result Register 0/4 High"},
  { 0x62, "ADREG15L",   "A/D Result Register 1 Low"},
  { 0x63, "ADREG15H",   "A/D Result Register 1 High"},
  { 0x64, "ADREG26L",   "A/D Result Register 2 Low"},
  { 0x65, "ADREG26H",   "A/D Result Register 2 High"},
  { 0x66, "ADREG37L",   "A/D Result Register 3 Low"},
  { 0x67, "ADREG37H",   "A/D Result Register 3 High"},
  { 0x68, "B0CS",       "Block 0 CS/WAIT Control Register"},
  { 0x69, "B1CS",       "Block 1 CS/WAIT Control Register"},
  { 0x6A, "B2CS",       "Block 2 CS/WAIT Control Register"},
  { 0x6D, "CKOCR",      "Clock Output Control Register"},
  { 0x6E, "SYSCR0",     "System Clock Register 0"},
  { 0x6F, "SYSCR1",     "System Clock Contol Register 1"},
  { 0x70, "INTE0AD",    "Interrupt Enable 0 & A/D"},
  { 0x71, "INTE45",     "Interrupt Enable 4/5"},
  { 0x72, "INTE67",     "Interrupt Enable 6/7"},
  { 0x73, "INTET10",    "Interrupt Enable Timer 1/0"},
  { 0x74, "INTE89",     "Interrupt Enable 8/9"},
  { 0x75, "INTET54",    "Interrupt Enable 5/4"},
  { 0x76, "INTET76",    "Interrupt Enable 7/6"},
  { 0x77, "INTES0",     "Interrupt Enable Serial 0"},
  { 0x78, "INTES1",     "Interrupt Enable Serial 1"},
  { 0x7B, "IIMC",       "Interrupt Input Mode Control"},
  { 0x7C, "DMA0V",      "DMA 0 Reauest Vector"},
  { 0x7D, "DMA1V",      "DMA 1 Request Vector"},
  { 0x7E, "DMA2V",      "DMA 2 Request Vector"},
  { 0x7F, "DMA3V",      "DMA 3 Request Vector"},
  { 0x00,  NULL  ,  NULL }
};

//----------------------------------------------------------------------
// проверить текстовое имя на предопределенность
static int IsPredefined(const char *name)
{
  const predefined_t *ptr;
  for ( ptr = iregs; ptr->name != NULL; ptr++ )
    if ( strcmp(ptr->name,name) == 0 ) return(1);
  return(0);
}

//----------------------------------------------------------------------
// получить по адресу имя
static const predefined_t *GetPredefined(predefined_t *ptr,uint32 addr)
{
  for ( ; ptr->name != NULL; ptr++ )
    if ( addr == ptr->addr )
      return(ptr);
  return(NULL);
}

//----------------------------------------------------------------------
// создать добавочный сегмент внутр. памяти
static uint32 AdditionalSegment(int size,int offset,char *name)
{
  segment_t s;
  s.startEA = freechunk(0,size,0xF);
  s.endEA   = s.startEA + size;
  s.sel     = ushort((s.startEA-offset) >> 4);
  s.type    = SEG_IMEM;                         // internal memory
  add_segm(&s,name,NULL,ADDSEG_NOSREG);
  // вернем начало сегмента
  return s.startEA - offset;
}

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
      set_segm_class(get_first_seg(),"CODE");
      // создадим два доп. сегмента
      AdditionalSegment(0x80,0,"SFR");         // сегмент регистров
      AdditionalSegment(0x800,0x80,"INTMEM");  // нутряная память
      // распишем весь sfr байтами
      for(ea_t ea=0;ea<0x80;ea++)doByte(ea,1);
      const predefined_t *ptr;
      // создадим все регистры в sfr'e и распишем все данные
      for ( ptr=iregs; ptr->name != NULL; ptr++ ){
                ea_t ea = ptr->addr;
                ea_t oldea = get_name_ea(ptr->name);
                if ( oldea != ea ) {
                        // есть другое имя - сотрем его
                        if ( oldea != BADADDR ) del_name(oldea);
                        // установим наше имя
                        set_name(ea,ptr->name);
                }
        // если есть коментарий - поставим коментарий
        if ( ptr->cmt != NULL ) set_cmt(ea,ptr->cmt,1);
      }
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
  AS_COLON | AS_UDATA | ASH_HEXF3 ,
  // пользовательские флажки
  0,
  "Generic IAR-style assembler",        // название ассемблера
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
  "DB",                                 // byte directive
  "DW",                                 // word directive
  "DL",                                 // dword  (4 bytes)
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
  "align"                               // ключ align
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
static const char *shnames[] = { "TLCS900", NULL };
// длинные имена процессоров
static const char *lnames[] = { "TLCS900", NULL };

//--------------------------------------------------------------------------
// коды возвратов из п/п
static uchar retcode_1[] = { 0x0E };    // ret
static uchar retcode_2[] = { 0x0F };    // ret d
static uchar retcode_3[] = { 0x07 };    // reti
static const bytes_t retcodes[] = {
 { sizeof(retcode_1), retcode_1 },
 { sizeof(retcode_2), retcode_2 },
 { sizeof(retcode_3), retcode_3 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH = {
  IDP_INTERFACE_VERSION,        // version
#if IDP_INTERFACE_VERSION > 37
  PLFM_TLCS900,                 // id процессора
  PR_USE32|PR_BINMEM|PR_SEGTRANS|PR_DEFSEG32,      // can use register names for byte names
  8,                                                    // 8 bits in a byte for code segments
#else
  0x8001,
  PR_USE32|PR_DEFSEG32,         // can use register names for byte names
#endif
  8,                            // 8 bits in a byte

  shnames,                      // короткие имена процессоров (до 9 символов)
  lnames,                       // длинные имена процессоров

  asms,                         // список компиляторов

  notify,                       // функция оповещения

  T900_header,                  // создание заголовка текста
  T900_footer,                  // создание конца текста

  T900_segstart,                // начало сегмента
  std_gen_segm_footer,          // конец сегмента - стандартный, без завершения

  NULL,                         // директивы смены сегмента - не используются

  T900_ana,                     // канализатор
  T900_emu,                     // эмулятор инструкций

  T900_out,                     // текстогенератор
  T900_outop,                   // тектогенератор операндов
  T900_data,                    // генератор описания данных
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
  0,T900_last,                  // первая и последняя инструкции
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
