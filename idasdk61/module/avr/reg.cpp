/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *      Atmel AVR - 8-bit RISC processor
 *
 */

#include "avr.hpp"
#include <srarea.hpp>
#include <diskio.hpp>
#include <loader.hpp>
#include <entry.hpp>
#include <fixup.hpp>
#include <fpro.h>
#include <ctype.h>
#include "../../ldr/elf/elfr_avr.h"

//--------------------------------------------------------------------------
static const char *register_names[] =
{
   "r0",   "r1",   "r2",  "r3",  "r4",  "r5",  "r6",  "r7",
   "r8",   "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
  "r16",  "r17",  "r18", "r19", "r20", "r21", "r22", "r23",
  "r24",  "r25",  "r26", "r27", "r28", "r29", "r30", "r31",
  "cs","ds",       // virtual registers for code and data segments
};

//-----------------------------------------------------------------------
//           AVR assembler
//-----------------------------------------------------------------------
static asm_t avrasm =
{
  AS_COLON|AS_N2CHR|ASH_HEXF3|ASD_DECF0|ASB_BINF3|ASO_OCTF0|AS_ONEDUP,
  0,
  "AVR Assembler",
  0,
  NULL,         // header lines
  NULL,         // no bad instructions
  ".org",       // org
  ".exit",      // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\"'",        // special symbols in char and string constants

  ".db",        // ascii string directive
  ".db",        // byte directive
  ".dw",        // word directive
  ".dd",        // double words
  NULL,         // no qwords
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".byte %s",   // uninited arrays
  ".equ",       // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  NULL,         // Pointer to checkarg_preline() function.
  NULL,         // char *(*checkarg_atomprefix)(char *operand,void *res); // if !NULL, is called before each atom
  NULL,         // const char **checkarg_operations;
  NULL,         // translation to use in character and string constants.
  NULL,         // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // "public" name keyword
  NULL,         // "weak"   name keyword
  NULL,         // "extrn"  name keyword
  NULL,         // "comm" (communal variable)
  NULL,         // get_type_name
  NULL,         // "align" keyword
  '(', ')',     // lbrace, rbrace
  NULL,         // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "~",          // not
  "<<",         // shl
  ">>",         // shr
  NULL,         // sizeof
};

static asm_t *asms[] = { &avrasm, NULL };

//--------------------------------------------------------------------------
static ioport_t *ports = NULL;
static size_t numports = 0;
static int subarch = 0;
static bool imageFile = false;
char device[MAXSTR] = "";
static const char cfgname[] = "avr.cfg";
netnode helper;

uint32 ramsize = 0;
uint32 romsize = 0;
uint32 eepromsize = 0;
ea_t ram = BADADDR;

static bool entry_processing(ea_t &ea1)
{
  helper.altset(ea1, 1);
  create_insn(ea1);
  ea_t ea = get_first_fcref_from(ea1);
  if ( ea != BADADDR ) ea1 = ea;
  return false; // continue processing
}
static const char *idaapi avr_callback(const ioport_t *ports, size_t numports, const char *line);
static bool ioresp_ok(void);
#define callback avr_callback
#define ENTRY_PROCESSING(ea, name, cmt)  entry_processing(ea)
#define CHECK_IORESP      ioresp_ok()
#include "../iocommon.cpp"

//--------------------------------------------------------------------------
static bool ioresp_ok(void)
{
  return inf.like_binary() || imageFile;
}

//--------------------------------------------------------------------------
static bool is_possible_subarch(int addr)
{
  // old version of gcc-arm don't use 31/51/etc subarches - only 3/5/... :(
  // maybe make option?
  return subarch == 0 || subarch == addr || (addr/10 == subarch);
}

//--------------------------------------------------------------------------
static const char *idaapi avr_callback(const ioport_t *ports, size_t numports, const char *line)
{
  char word[MAXSTR];
  int addr;
  if ( sscanf(line, "%[^=] = %d", word, &addr) == 2 )
  {
    if ( strcmp(word, "RAM") == 0 )
    {
      ramsize = addr;
      return NULL;
    }
    if ( strcmp(word, "ROM") == 0 )
    {
      romsize = addr >> 1;
      return NULL;
    }
    if ( strcmp(word, "EEPROM") == 0 )
    {
      eepromsize = addr;
      return NULL;
    }
    if ( strcmp(word, "SUBARCH") == 0 )
    {
      return is_possible_subarch(addr) ? NULL : IOPORT_SKIP_DEVICE;
    }
  }
  return standard_callback(ports, numports, line);
}

//--------------------------------------------------------------------------
static const char *idaapi parser(const char* line, char* /*buf*/, size_t /*buflen*/)
{
  char word[MAXSTR];
  int addr;

  return (   sscanf(line, "%[^=] = %d", word, &addr) == 2
          && strcmp(word, "SUBARCH") == 0
          && !is_possible_subarch(addr) ) ? IOPORT_SKIP_DEVICE : NULL;
}

//--------------------------------------------------------------------------
const char *find_port(ea_t address)
{
  const ioport_t *port = find_ioport(ports, numports, address);
  return port ? port->name : NULL;
}

//--------------------------------------------------------------------------
const char *find_bit(ea_t address, size_t bit)
{
  const ioport_bit_t *b = find_ioport_bit(ports, numports, address, bit);
  return b ? b->name : NULL;
}

//--------------------------------------------------------------------------
static void setup_avr_device(int respect_info)
{
  if ( !choose_ioport_device(cfgname, device, sizeof(device), NULL) )
    return;

  set_device_name(device, respect_info);
  if ( get_first_seg() == NULL )  // set processor options before load file
    return;
  noUsed(0, BADADDR); // reanalyze program

  // resize the ROM segment
  {
    segment_t *s = getseg(helper.altval(-1));
    if ( s == NULL )
      s = get_first_seg();  // for the old databases
    if ( s != NULL )
    {
      if ( s->size() > romsize )
        warning("The input file is bigger than the ROM size of the current device");
      set_segm_end(s->startEA, s->startEA+romsize, SEGMOD_KILL);
    }
  }
  // resize the RAM segment
  {
    segment_t *s = get_segm_by_name("RAM");
    if ( s == NULL && ramsize != 0 )
    {
      ea_t start = (inf.maxEA + 0xFFFFF) & ~0xFFFFF;
      add_segm(start>>4, start, start+ramsize, "RAM", "DATA");
      s = getseg(start);
    }
    ram = BADADDR;
    if ( s != NULL )
    {
      int i;
      ram = s->startEA;
      set_segm_end(ram, ram+ramsize, SEGMOD_KILL);
      // set register names
      for ( i=0; i < 32; i++ )
        if ( !has_any_name(get_flags_novalue(ram+i)) )
          set_name(ram+i, register_names[i]);
      // set I/O port names
      for ( i=0; i < numports; i++ )
      {
        ioport_t *p = ports + i;
        set_name(ram+p->address+0x20, p->name);
        set_cmt(ram+p->address+0x20, p->cmt, true);
      }
    }
  }
}

//--------------------------------------------------------------------------
const char *idaapi set_idp_options(const char* keyword, int value_type, const void* value)
{
  if ( keyword == NULL )
  {
    setup_avr_device(IORESP_INT);
    return IDPOPT_OK;
  }
  else if ( strcmp(keyword, "AVR_MCPU") == 0 )
  {
    if ( value_type != IDPOPT_STR )
      return IDPOPT_BADTYPE;

    qstrncpy(device, (const char*)value, sizeof(device));
    return IDPOPT_OK;
  }

  return IDPOPT_BADKEY;
}

//--------------------------------------------------------------------------
static bool set_param_by_arch(void)
{
    int max_rom, max_ram, max_eeprom;
    // preset MAXIMUM's of memory size's by mcpu subtype
    switch ( subarch )
    {
      default:
        subarch = 0;
        return false; // LOGICAL ERROR?

      // at90s1200, attiny10, attiny11, attiny12, attiny15, attiny28
      case E_AVR_MACH_AVR1: // ROM<=1k
        max_rom     = 1024;
        max_ram     = 32;
        max_eeprom  = 64;
        break;
      // at90s2313, at90s2323, at90s2333, at90s2343, attiny22, attiny26,
      // at90s4414 /* XXX -> 8515 */, at90s4433, at90s4434 /* XXX -> 8535 */,
      // at90s8515, at90c8534, at90s8535
      case E_AVR_MACH_AVR2: // ROM<=8k
      // attiny13, attiny13a, attiny2313, attiny24, attiny44, attiny84,
      // attiny25, attiny45, attiny85, attiny261, attiny461, attiny861,
      // attiny43u, attiny48, attiny88, at86rf401
  // PASS THRU
      case E_AVR_MACH_AVR25:  // ROM<=8k
        max_rom     = 8*1024;
        max_ram     = 512;
        max_eeprom  = 512;
        break;
        // at43usb355, at76c711
      case E_AVR_MACH_AVR3:   // ROM>=8k<=64k
        max_rom     = 64*1024;
        max_ram     = 1024;
        max_eeprom  = 0;
        break;
      // atmega103,  at43usb320,
      case E_AVR_MACH_AVR31:  // ROM>=65k&&<=128k, (RAM=65k, EEPROM=4k)
        max_rom     = 128*1024;
        max_ram     = 4*1024;
        max_eeprom  = 4*1024;
        break;
      // attiny167, at90usb82, at90usb162
      case E_AVR_MACH_AVR35:  // ROM>=8k&&<=64k,
        max_rom     = 64*1024;
        max_ram     = 512;
        max_eeprom  = 512;
        break;
      // atmega8, atmega48, atmega48p, atmega88, atmega88p, atmega8515,
      // atmega8535, atmega8hva, at90pwm1, at90pwm2, at90pwm2b, at90pwm3,
      // at90pwm3b
      case E_AVR_MACH_AVR4:   // ROM<=8k
        max_rom     = 8*1024;
        max_ram     = 1024;
        max_eeprom  = 512;
        break;
      // atmega16, atmega161, atmega162, atmega163, atmega164p, atmega165,
      // atmega165p, atmega168, atmega168p, atmega169, atmega169p, atmega32,
      // atmega323, atmega324p, atmega325, atmega325p, atmega3250, atmega3250p,
      // atmega328p, atmega329, atmega329p, atmega3290, atmega3290p, atmega406,
      // atmega64, atmega640, atmega644, atmega644p, atmega645, atmega649,
      // atmega6450, atmega6490, atmega16hva, at90can32, at90can64, at90pwm216,
      // at90pwm316, atmega32c1, atmega32m1, atmega32u4, at90usb646, at90usb647,
      // at94k
      case E_AVR_MACH_AVR5:   // ROM>=8k&&<=64k
        max_rom     = 64*1024;
        max_ram     = 4*1024;
        max_eeprom  = 2*1024;
        break;
      // atmega128, atmega1280, atmega1281, atmega1284p,
      // at90can128, at90usb1286, at90usb1287
      case E_AVR_MACH_AVR51:  // ROM=128k
        max_rom     = 128*1024;
        max_ram     = 16*1024;
        max_eeprom  = 4*1024;
        break;
      // atmega2560, atmega2561
      case E_AVR_MACH_AVR6:   // ROM=256k (3-byte pc -- is supported?)
        max_rom     = 256*1024;
        max_ram     = 8*1024;
        max_eeprom  = 4*1024;
        break;
      case E_AVR_MACH_XMEGA1: // ROM < 8K, ram=?
        max_rom     = 8*1024;
        max_ram     = 1024;
        max_eeprom  = 512;
        break;
      // ATxmega16A4, ATxmega16D4, ATxmega32D4
      case E_AVR_MACH_XMEGA2: // 8K < FLASH <= 64K, RAM <= 64K
        max_rom     = 64*1024;
        max_ram     = 64*1024;
        max_eeprom  = 1024;
        break;
      // ATxmega32A4
      case E_AVR_MACH_XMEGA3: // 8K < FLASH <= 64K, RAM > 64K
        max_rom     = 64*1024;
        max_ram     = 128*1024; // ?
        max_eeprom  = 1024;
        break;
      // ATxmega64A3, ATxmega64D3
      case E_AVR_MACH_XMEGA4: // 64K < FLASH <= 128K, RAM <= 64K
        max_rom     = 128*1024;
        max_ram     = 64*1024;
        max_eeprom  = 2048;
        break;
      // ATxmega64A1
      case E_AVR_MACH_XMEGA5: // 64K < FLASH <= 128K, RAM > 64K
        max_rom     = 128*1024;
        max_ram     = 128*1024;
        max_eeprom  = 2048;
        break;
      // ATxmega128A3, ATxmega128D3, ATxmega192A3, ATxmega192D3,
      // ATxmega256A3B, ATxmega256A3, ATxmega256D3
      case E_AVR_MACH_XMEGA6: // 128K < FLASH <= 256K, RAM <= 64K
        max_rom     = 256*1024;
        max_ram     = 64*1024;
        max_eeprom  = 4096;
        break;
      // ATxmega128A1
      case E_AVR_MACH_XMEGA7: // 128K < FLASH <= 256K, RAM > 64K
        max_rom     = 256*1024;
        max_ram     = 128*1024;
        max_eeprom  = 4096;
        break;
    }
    if ( !choose_ioport_device(cfgname, device, sizeof(device), parser) )
    {
      qsnprintf(device, sizeof(device), "avr%d", subarch);
      device[sizeof("avrX")-1] = '\0';
      romsize    = max_rom >> 1;
      ramsize    = max_ram;
      eepromsize = max_eeprom;
    }
    else
    {
      set_device_name(device, IORESP_INT);
      noUsed(0, BADADDR); // reanalyze program
    }
    return true;
}

//--------------------------------------------------------------------------
static inline ea_t get16bit(ea_t ea)
{
    if ( segtype(ea) == SEG_CODE )
      return get_full_byte(ea);

    return get_word(ea);
}

//--------------------------------------------------------------------------
static int idaapi idb_callback(void *, int code, va_list va)
{
  switch ( code )
  {
    case idb_event::segm_added:
      {
        segment_t *s = va_arg(va, segment_t *);
        char sclass[32];
        if ( get_segm_class(s, sclass, sizeof(sclass)) > 0 && strcmp(sclass, "DATA") == 0 )
          set_default_dataseg(s->sel);
      }
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
static int notify(processor_t::idp_notify msgid, ...)
{
  static bool nonBinary;

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
    case processor_t::init:
      helper.create(AVR_INFO_NODENAME);
      hook_to_notification_point(HT_IDB, idb_callback, NULL);
    default:
      break;

    case processor_t::term:
      unhook_from_notification_point(HT_IDB, idb_callback, NULL);
      free_ioports(ports, numports);
      break;

    case processor_t::loader:   // elf-loader 'set machine type' and file type
      subarch   = va_arg(va, int);
      imageFile = va_argi(va, bool);
      nonBinary = true;
      break;

    case processor_t::newfile:   // new file loaded
      // remember the ROM segment
      {
        segment_t *s = get_first_seg();
        if ( s != NULL )
        {
          if ( subarch == 0 )
            set_segm_name(s, "ROM");
          helper.altset(-1, s->startEA);
        }
      }
      if ( subarch != 0 && set_param_by_arch() )
        break;
      apply_config_file(IORESP_NONE);  // just in case if the user refuses to select
      setup_avr_device(/*IORESP_AREA|*/IORESP_INT); // allow the user to select the device
      if ( subarch != 0 )
        break;
      // create additional segments
      {
        ea_t start = (inf.maxEA + 0xFFFFF) & ~0xFFFFF;
        if ( eepromsize != 0 )
        {
          char *file = askfile_c(0,"*.bin","Please enter the binary EEPROM image file");
          if ( file != NULL )
          {
            add_segm(start>>4, start, start+eepromsize, "EEPROM", "DATA");
            linput_t *li = open_linput(file, false);
            if ( li != NULL )
            {
              uint32 size = qlsize(li);
              if ( size > eepromsize ) size = eepromsize;
              file2base(li, 0, start, start+size, FILEREG_NOTPATCHABLE);
              close_linput(li);
            }
          }
        }
      }
      break;

    case processor_t::oldfile:   // old file loaded
      {
        char buf[MAXSTR];
        if ( helper.supval(-1, buf, sizeof(buf)) > 0 )
          set_device_name(buf, IORESP_NONE);
        segment_t *s = get_segm_by_name("RAM");
        if ( s != NULL )
          ram = s->startEA;
      }
      break;

    case processor_t::newprc:    // new processor type
      break;

    case processor_t::newasm:    // new assembler type
      break;

    case processor_t::outlabel: // The kernel is going to generate an instruction
                                // label line or a function header
      {
        ea_t ea = va_arg(va, ea_t);
        if ( helper.altval(ea) ) // if entry point
        {
          char buf[MAX_NUMBUF];
          btoa(buf, sizeof(buf), ea);
          printf_line(inf.indent, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
        }
      }
      break;

    case processor_t::move_segm:// A segment is moved
                                // Fix processor dependent address sensitive information
                                // args: ea_t from - old segment address
                                //       segment_t - moved segment
      {
        ea_t from    = va_arg(va, ea_t);
        segment_t *s = va_arg(va, segment_t *);
        helper.altshift(from, s->startEA, s->size()); // move address information
      }
      break;

    case processor_t::custom_fixup: // special processing of relocatable file (elf, bladox)
      {
        processor_t::cust_fix oper = va_argi(va, processor_t::cust_fix);
        ea_t                  ea   = va_arg(va, ea_t);
        const fixup_data_t*   fd   = va_arg(va, const fixup_data_t*);
        if (   !nonBinary
            || (fd->type & (FIXUP_REL|FIXUP_UNUSED)) != 0
            || fd->displacement != 0)
        {
cf_invalid:
          msg("%a: Unexpected or incorrect CUSTOM_FIXUP (req=%d)\n", ea, oper);
          break;
        }
        // currently used only for 'replaced' FIXUP_OFF16 to dataseg/externs
        switch ( oper )
        {
          default:
            goto cf_invalid;

          case processor_t::cf_base:        // Get fixup base
            *va_arg(va, ea_t*) = sel2ea(fd->sel); // args: ea_t *answer
            break;

          case processor_t::cf_size:        // Get fixup size
            *va_arg(va, int*) = 2;          // args: int *answer
            break;

          case processor_t::cf_desc:        // Describe fixup
            {                               // args: char *buf, size_t bufsize
              char *buf = va_arg(va, char*),
                   *end = buf + va_arg(va, size_t);
              char name[qmax(MAXNAMELEN,MAXSTR)];
              stoa(ea, fd->sel, name, sizeof(name));
              append_snprintf(buf, end, "OFF16 %sDEF [%s,%a]",
                              (fd->type & FIXUP_EXTDEF) ? "EXT" : "SEG",
                              name, fd->off);
              if ( fd->type & FIXUP_EXTDEF )
              {
                ea = sel2ea(fd->sel) + fd->off;
                if ( get_short_name(ea, ea, name, sizeof(name)) == NULL )
                  name[0] = '\0';
                append_snprintf(buf, end, "=%a (%s)", ea, name);
              }
            }
            break;

          case processor_t::cf_apply:       // Apply a fixup
            {                               // args: ea_t item_start, int opnum
              refinfo_t ri;
              ri.flags = REF_OFF16 | REFINFO_CUSTOM;
              ri.tdelta = 0;  // fd.displacement;
              ri.target = (ri.base = sel2ea(fd->sel)) + fd->off;
              ea_t sea = va_arg(va, ea_t);
              if ( isUnknown(get_flags_novalue(sea)) ) do16bit(sea, 2);
              op_offset_ex(sea, va_arg(va, int), &ri);
            }
            break;

          case processor_t::cf_move:        // Relocate the fixup
            {                               // may be called from loader_t.move_segm()
              fixup_data_t nfd(*fd);        // args: adiff_t delta
              nfd.off += va_arg(va, adiff_t);
              nfd.off &= 0xFFFF;
              put_word(ea, nfd.off);
              set_fixup(ea, &nfd);
            }
            break;
        }
      }
      return 2;

    case processor_t::off_preproc:  // called from get_offset_expr, for custom_fixup
      {
        ea_t              ea      = va_arg(va, ea_t);
        int               numop   = va_arg(va, int);
        ea_t*             opval   = va_arg(va, ea_t*);
        const refinfo_t*  ri      = va_arg(va, refinfo_t*);
//        char*             buf     = va_arg(va, char*);
//        size_t            bufsize = va_arg(va, size_t);
//        ea_t*             target  = va_arg(va, ea_t*);
//        ea_t*             fullval = va_arg(va, ea_t*);
//        ea_t              from    = va_arg(va, ea_t);
//        int               getn_fl = va_arg(va, int);
        if (   !nonBinary
            || numop != 0
            || ri->flags != (REF_OFF16 | REFINFO_CUSTOM)
            || ri->tdelta != 0
            || ri->target == BADADDR
            || *opval != get16bit(ea) )
        {
          msg("%a: Unexpected or incorrect CUSTOM offset\n", ea);
          break;
        }
        *opval |= (ri->target & ~0xFFFF);
      }
      return 4; // process offset with standard mode
  }
  va_end(va);
  return 1;
}

//--------------------------------------------------------------------------
// 1001 0101 0xx0 1000     ret
// 1001 0101 0xx1 1000     reti
static uchar retcode_1[] = { 0x08, 0x95 };  // ret
static uchar retcode_2[] = { 0x18, 0x95 };  // reti
static uchar retcode_3[] = { 0x28, 0x95 };  // ret
static uchar retcode_4[] = { 0x38, 0x95 };  // reti
static uchar retcode_5[] = { 0x48, 0x95 };  // ret
static uchar retcode_6[] = { 0x58, 0x95 };  // reti
static uchar retcode_7[] = { 0x68, 0x95 };  // ret
static uchar retcode_8[] = { 0x78, 0x95 };  // reti

static bytes_t retcodes[] =
{
 { sizeof(retcode_1), retcode_1 },
 { sizeof(retcode_2), retcode_2 },
 { sizeof(retcode_3), retcode_3 },
 { sizeof(retcode_4), retcode_4 },
 { sizeof(retcode_5), retcode_5 },
 { sizeof(retcode_6), retcode_6 },
 { sizeof(retcode_7), retcode_7 },
 { sizeof(retcode_8), retcode_8 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
static const char *shnames[] =
{
  "AVR",
  NULL
};

static const char *lnames[] =
{
  "Atmel AVR",
  NULL
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_AVR,                     // id
  PRN_HEX|PR_RNAMESOK,
  16,                   // 16 bits in a byte for code segments
  8,                    // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  header,
  footer,

  segstart,
  segend,

  NULL,                 // generate "assume" directives

  ana,                  // analyze instruction
  emu,                  // emulate instruction

  out,                  // generate text representation of instruction
  outop,                // generate ...                    operand
  intel_data,           // generate ...                    data directive
  NULL,                 // compare operands
  NULL,                 // can have type

  qnumber(register_names), // Number of registers
  register_names,       // Register names
  NULL,                 // get abstract register

  0,                    // Number of register files
  NULL,                 // Register file names
  NULL,                 // Register descriptions
  NULL,                 // Pointer to CPU registers

  rVcs,                 // first
  rVds,                 // last
  0,                    // size of a segment register
  rVcs, rVds,

  NULL,                 // No known code start sequences
  retcodes,

  AVR_null,
  AVR_last,
  Instructions,

  NULL,                 // int  (*is_far_jump)(int icode);
  NULL,                 // Translation function for offsets
  0,                    // int tbyte_size;  -- doesn't exist
  NULL,                 // int (*realcvt)(void *m, ushort *e, ushort swt);
  { 0, },               // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  NULL,                 // int (*is_switch)(switch_info_t *si);
  NULL,                 // int32 (*gen_map_file)(FILE *fp);
  NULL,                 // ea_t (*extract_address)(ea_t ea,const char *string,int x);
  NULL,                 // int (*is_sp_based)(op_t &x); -- always, so leave it NULL
  NULL,                 // int (*create_func_frame)(func_t *pfn);
  NULL,                 // int (*get_frame_retsize(func_t *pfn)
  NULL,                 // void (*gen_stkvar_def)(char *buf,const member_t *mptr,int32 v);
  gen_spcdef,           // Generate text representation of an item in a special segment
  AVR_ret,              // Icode of return instruction. It is ok to give any of possible return instructions
  set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
  NULL,                 // int (*is_align_insn)(ea_t ea);
  NULL,                 // mvm_t *mvm;
};
