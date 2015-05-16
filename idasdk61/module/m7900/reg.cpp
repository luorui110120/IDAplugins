

/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include <ctype.h>
#include "7900.hpp"
#include <diskio.hpp>
#include <entry.hpp>

//extern int gFlag_M;
//extern int gFlag_X;

//----------------------------------------------------------------------
static const char *RegNames[] = {
  "A", "B", "E", "X", "Y", "PC",  "S",
  "fIPL", "fN", "fV", "fD", "fI", "fZ", "fC",
  "DT", "PG", "DPReg", "DPR0","DPR1", "DPR2","DPR3","fM", "fX",
  "cs",  "ds"
};




//----------------------------------------------------------------------
static asm_t AS79 = {
  AS_COLON |            // create colons after data names ?
                        // ASCII directives:
  AS_1TEXT  |           //   1 text per line, no bytes
  ASH_HEXF0 |           // format of hex numbers://   34h
  ASD_DECF0 |           // format of dec numbers://   34
  ASB_BINF0 |           // format of binary numbers://   010101b
  AS_ONEDUP,            // One array definition per line

  UAS_NOSPA | UAS_SEGM,
  "Mitsubishi AS79 V4.10",
  0,
  NULL,     //header
  NULL,
  ".org",
  ".end",

  ";",        // comment string
  '"',        // string delimiter
  '\'',       // char delimiter
  "'\"",      // special symbols in char and string constants

  ".BYTE",    // ascii string directive
  ".BYTE",    // byte directive
  ".WORD",    // word directive
  ".DWORD",   // no double words
  NULL,       // no qwords
  NULL,       // oword  (16 bytes)
  NULL,       // no float
  NULL,       // no double
  NULL,       // no tbytes
  NULL,       // no packreal
  NULL,       //".db.#s(b,w) #d,#v",   // #h - header(.byte,.word)
                    // #d - size of array
                    // #v - value of array elements
                    // #s - size specifier
  ".rs %s",     // uninited data (reserve space)
  ".equ",
  NULL,         // seg prefix
  NULL,         // preline for checkarg
  NULL,         // checkarg_atomprefix
  NULL,         // checkarg operations
  NULL,         // XlatAsciiOutput
  "*",          // a_curip
  NULL,         // returns function header line
  NULL,         // returns function footer line
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
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
  "m7900",
  NULL
};

static const char *lnames[] =
{
  "7700 Family / 7900 Series",
  NULL
};


static asm_t *asms[] =
{
  &AS79,
  NULL
};

//--------------------------------------------------------------------------
//Коды возвратов
static uchar retc_0[] = { 0xF1 };    //rti
static uchar retc_1[] = { 0x94 };    //rtl
static uchar retc_2[] = { 0x1C, 0x77 };    //rtld 0
static uchar retc_3[] = { 0x2C, 0x77 };    //rtld 1
static uchar retc_4[] = { 0x4C, 0x77 };    //rtld 2
static uchar retc_5[] = { 0x8C, 0x77 };    //rtld 3
static uchar retc_6[] = { 0x84 };    //rts
static uchar retc_7[] = { 0x18, 0x77 };    //rtsd 0
static uchar retc_8[] = { 0x28, 0x77 };    //rtsd 1
static uchar retc_9[] = { 0x48, 0x77 };    //rtsd 2
static uchar retc_10[] = { 0x88, 0x77 };    //rtsd 3
static uchar retc_11[] = { 0x00, 0x74 };    //brk

static bytes_t retcodes[] = {
 { sizeof(retc_0), retc_0 },
 { sizeof(retc_1), retc_1 },
 { sizeof(retc_2), retc_2},
 { sizeof(retc_3), retc_3 },
 { sizeof(retc_4), retc_4 },
 { sizeof(retc_5), retc_5 },
 { sizeof(retc_6), retc_6 },
 { sizeof(retc_6), retc_7 },
 { sizeof(retc_6), retc_8 },
 { sizeof(retc_9), retc_9 },
 { sizeof(retc_10), retc_10 },
 { sizeof(retc_11), retc_11 },

 { 0, NULL }
};


//----------------------------------------------------------------------
static netnode helper;
char device[MAXSTR] = "";
static size_t numports;
static ioport_t *ports;


#include "../iocommon.cpp"

#define ADDRRESET 0xFFFE

const char *idaapi set_idp_options(
    const char *keyword,
    int /*value_type*/,
    const void * /*value*/ )
{
    if ( keyword != NULL )
        return IDPOPT_BADKEY;

    char cfgfile[QMAXFILE];
    get_cfg_filename(cfgfile, sizeof(cfgfile));
    if ( !choose_ioport_device(cfgfile, device, sizeof(device), NULL)
      && strcmp(device, NONEPROC) == 0 )
    {
      warning("No devices are defined in the configuration file %s", cfgfile);
    }

    set_device_name(device, IORESP_PORT|IORESP_INT );

    return IDPOPT_OK;
}


inline static bool choose_device()
{
    char cfgfile[QMAXFILE];
    get_cfg_filename(cfgfile, sizeof(cfgfile));
    bool ok = choose_ioport_device(cfgfile, device, sizeof(device), parse_area_line0);
    if ( !ok )
    {
        qstrncpy(device, NONEPROC, sizeof(device));

        segment_t *sptr = get_first_seg();
        if ( sptr != NULL )
        {

          //inf.beginEA = sptr->startEA;
          //inf.startIP = 0;

          //Значит не выбрали не какого процесора
          //то создадим сами RESET
          //В документации на семейство 7900 сказано
          //что RESET распологается по адрессу 0xFFFE
          doWord(ADDRRESET, 2);
          ea_t proc = get_word(ADDRRESET);
          if ( proc != 0xFFFF && isEnabled(proc) )
          {
             set_offset(ADDRRESET, 0, 0);
             add_entry(proc, proc, "__RESET", true);
             set_cmt(ADDRRESET, "RESET", false);
          }
        }
    }
    return ok;
}


//------------------------------------------------------------------
bool mitsubishi_find_ioport_bit(int port, int bit)
{
  //поиск бита из регистра в списке портов
  const ioport_bit_t *b = find_ioport_bit(ports, numports, port, bit);
  if ( b != NULL && b->name != NULL )
  {
    //выводим имя бита из регистра
    out_line(b->name, COLOR_IMPNAME);
    return true;
  }
  return false;
}


static char m7900_help_message[] =
    "AUTOHIDE REGISTRY\n"
    "You have loaded a file for the Mitsubishi 7900 family processor.\n\n"\
    "This processor can be used in two different 'length modes' : 8-bit and 16-bit.\n"\
    "IDA allows to specify the encoding mode for every single instruction.\n"\
    "For this, IDA uses two virtual segment registers : \n"\
    "   - rDPReg(1),  - rDPR0(0), rDPR1(0), rDPR2(0), rDPR3(0) \n"\
    "   - rDT(0),  rPG(0),  rPC(0),  rPS(0)   \n"\
    "   - fM, used to specify the data length;(0)\n"\
    "   - fX, used to specify the index register length.(0)\n\n"\
    "Switching their state from 0 to 1 will switch the disassembly from 16-bit to 8-bit.\n"\
    "You can change their value using the 'change segment register value' command"\
    "(the canonical hotkey is Alt-G).\n\n"\
    "Note : in the real design, those registers are represented as flags in the\n"\
    "processor status register.\n";


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

  switch ( msgid )
  {

    case processor_t::newfile:
     {
       helper.create("$ m7900");

      //функция "выбирает" из указанного файла *.cfg все записи(процессора)
      //и отображает их в диалоговом окне, в котором пользователь может выбрать
      //нужный ему процессор. После выбора имя процессора заносится в переменную device
      //По умолчанию в DLG выделен процессор который указан в переменной .default
      //которая распологается в начале файла *.cfg
      if ( choose_device() )
         //Устанавливает в ядре иды имя выбранного процессора
         //Вычитывает все "записи"(порты)  относящиеся к этому процессору
         //И подписывает в файле все байты вычитанные из *.cfg файла
          set_device_name(device, IORESP_ALL);

        //  Set the default segment register values :
        //      -1 (badsel) for DR
        //      0 for fM and fX
         for ( segment_t *s=get_first_seg(); s != NULL; s=get_next_seg(s->startEA) )
             {
                SetDefaultRegisterValue(s, rDPR0, 0x0);
                SetDefaultRegisterValue(s, rDPR1, 0x0);
                SetDefaultRegisterValue(s, rDPR2, 0x0);
                SetDefaultRegisterValue(s, rDPR3, 0x0);
                SetDefaultRegisterValue(s, rDT, 0x0);
                SetDefaultRegisterValue(s, rPG, 0x0);
                SetDefaultRegisterValue(s, rPC, 0xFFFE);
                SetDefaultRegisterValue(s, rPS, 0x0FFF);

                SetDefaultRegisterValue(s, rfI, 1);
                SetDefaultRegisterValue(s, rfD, 0);
                SetDefaultRegisterValue(s, rfX, 0);
                SetDefaultRegisterValue(s, rfM, 0);
                SetDefaultRegisterValue(s, rfIPL, 0);

                SetDefaultRegisterValue(s, rDPReg, 1);
            }

         info(m7900_help_message);
     }
     break;

    case processor_t::term:
        free_ioports(ports, numports);
    default:
        break;


    case processor_t::newprc:
        {
          char buf[MAXSTR];
          if ( helper.supval(-1, buf, sizeof(buf)) > 0 )
            set_device_name(buf, IORESP_PORT);
        }
        break;

    case processor_t::newseg:    // new segment
        {
         segment_t *s = va_arg(va, segment_t *);
         // Set default value of DS register for all segments
         set_default_dataseg(s->sel);
        }
      break;


     //В процессоре изменился один из сегментных регистров
     //если это были fM или fX то начиная с адресса на котором сейчас находимся
     //(находится курсор) делаем данные неизвестными
     case processor_t::setsgr:
      {
          int reg  = va_arg(va, int); //Регистр (номер относительно RegName)
          if ( reg == rfM || reg == rfX || reg == rDT || reg == rPG  )
          {
//          msg("Deleting instructions in range %08a..%08a\n",ea1, ea2);
//          for (ea_t x = ea1; x < ea2; x = nextthat(x, ea2, isCode))
//            do_unknown(x, DOUNK_SIMPLE);
          }
       }
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
  IDP_INTERFACE_VERSION,
  PLFM_M7900,            // id
  PR_RNAMESOK|           // can use register names for byte names
  PR_BINMEM|             // The module creates RAM/ROM segments for binary files
                         // (the kernel shouldn't ask the user about their sizes and addresses)
  PR_SEGS|               // has segment registers?
  PR_SGROTHER,           // the segment registers don't contain
                         // the segment selectors, something else

  8,                    // 8 bits in a byte for code segments
  8,                    // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  header,
  footer,

  gen_segm_header,
  std_gen_segm_footer,

  NULL,

  ana,
  emu,

  out,
  outop,
  intel_data,
  NULL,         //  cmp_opnd,  // 0 if not cmp 1 if eq
  NULL,         //  can_have_type,  //&op    // 1 -yes 0-no    //reg

  qnumber(RegNames),            // Number of registers
  RegNames,                     // Regsiter names
  NULL,                         // get abstract register

  0,                            // Number of register files
  NULL,                         // Register file names
  NULL,
  NULL,                         // Pointer to CPU registers

  rDT,
  Rds,
  0,                            // size of a segment register
  Rcs,Rds,

  NULL,                         // No known code start sequences
  retcodes,

  0,
  m7900_last,
  Instructions,

  NULL,                 // int  (*is_far_jump)(int icode);
  NULL,                 // Translation function for offsets
  3,                    // int tbyte_size;  -- doesn't exist

  NULL,                 // int (*realcvt)(void *m, ushort *e, ushort swt);
  { 0, 0, 0, 0 },       // char real_width[4];
                            // number of symbols after decimal point
                            // 2byte float (0-does not exist)
                            // normal float
                            // normal double
                            // long double
  NULL,                 // int (*is_switch)(switch_info_t *si);
  NULL,                 // int32 (*gen_map_file)(FILE *fp);
  NULL,                 // ea_t (*extract_address)(ea_t ea,const char *string,int x);
  NULL,                 // int (*is_sp_based)(op_t &x);
  NULL,                 // int (*create_func_frame)(func_t *pfn);
  NULL,                 // int (*get_frame_retsize(func_t *pfn)
  NULL,                 // void (*gen_stkvar_def)(char *buf,const member_t *mptr,long v);
  NULL,                 // Generate text representation of an item in a special segment
  m7900_rts,            // Icode of return instruction. It is ok to give any of possible return instructions
  set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
  NULL,                 // int (*is_align_insn)(ea_t ea);
  NULL                  // mvm_t *mvm;
};
