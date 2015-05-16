
// x86-specific code (compiled only on IDA side, never on the server side)

#include <dbg.hpp>
#include "deb_pc.hpp"

//--------------------------------------------------------------------------
//
//      DEBUGGER REGISTER AND INSTRUCTION INFORMATIONS
//
//--------------------------------------------------------------------------

const char *x86_register_classes[] =
{
  "General registers",
  "Segment registers",
  "FPU registers",
  "MMX registers",
  "XMM registers",
  NULL
};


static const char *const eflags[] =
{
  "CF",         //  0
  NULL,         //  1
  "PF",         //  2
  NULL,         //  3
  "AF",         //  4
  NULL,         //  5
  "ZF",         //  6
  "SF",         //  7
  "TF",         //  8
  "IF",         //  9
  "DF",         // 10
  "OF",         // 11
  "IOPL",       // 12
  "IOPL",       // 13
  "NT",         // 14
  NULL,         // 15
  "RF",         // 16
  "VM",         // 17
  "AC",         // 18
  "VIF",        // 19
  "VIP",        // 20
  "ID",         // 21
  NULL,         // 22
  NULL,         // 23
  NULL,         // 24
  NULL,         // 25
  NULL,         // 26
  NULL,         // 27
  NULL,         // 28
  NULL,         // 29
  NULL,         // 30
  NULL          // 31
};

static const char *const ctrlflags[] =
{
  "IM",
  "DM",
  "ZM",
  "OM",
  "UM",
  "PM",
  NULL,
  NULL,
  "PC",
  "PC",
  "RC",
  "RC",
  "X",
  NULL,
  NULL,
  NULL
};

static const char *const statflags[] =
{
  "IE",
  "DE",
  "ZE",
  "OE",
  "UE",
  "PE",
  "SF",
  "ES",
  "C0",
  "C1",
  "C2",
  "TOP",
  "TOP",
  "TOP",
  "C3",
  "B"
};

static const char *const tagsflags[] =
{
  "TAG0",
  "TAG0",
  "TAG1",
  "TAG1",
  "TAG2",
  "TAG2",
  "TAG3",
  "TAG3",
  "TAG4",
  "TAG4",
  "TAG5",
  "TAG5",
  "TAG6",
  "TAG6",
  "TAG7",
  "TAG7"
};

static const char *const xmm_format[] =
{
  "XMM_4_floats",
};

static const char *const mmx_format[] =
{
  "MMX_8_bytes",
};

static const char *const mxcsr_bits[] =
{
  "IE",         //  0 Invalid Operation Flag
  "DE",         //  1 Denormal Flag
  "ZE",         //  2 Divide-by-Zero Flag
  "OE",         //  3 Overflow Flag
  "UE",         //  4 Underflow Flag
  "PE",         //  5 Precision Flag
  "DAZ",        //  6 Denormals Are Zeros*
  "IM",         //  7 Invalid Operation Mask
  "DM",         //  8 Denormal Operation Mask
  "ZM",         //  9 Divide-by-Zero Mask
  "OM",         // 10 Overflow Mask
  "UM",         // 11 Underflow Mask
  "PM",         // 12 Precision Mask
  "RC",         // 13 Rounding Control
  "RC",         // 14 Rounding Control
  "FZ",         // 15 Flush to Zero
  NULL,         // 16
  NULL,         // 17
  NULL,         // 18
  NULL,         // 19
  NULL,         // 20
  NULL,         // 21
  NULL,         // 22
  NULL,         // 23
  NULL,         // 24
  NULL,         // 25
  NULL,         // 26
  NULL,         // 27
  NULL,         // 28
  NULL,         // 29
  NULL,         // 30
  NULL          // 31
};


register_info_t x86_registers[] =
{
  // FPU registers
  { "ST0",    0,                            X86_RC_FPU,      dt_tbyte, NULL,   0 },
  { "ST1",    0,                            X86_RC_FPU,      dt_tbyte, NULL,   0 },
  { "ST2",    0,                            X86_RC_FPU,      dt_tbyte, NULL,   0 },
  { "ST3",    0,                            X86_RC_FPU,      dt_tbyte, NULL,   0 },
  { "ST4",    0,                            X86_RC_FPU,      dt_tbyte, NULL,   0 },
  { "ST5",    0,                            X86_RC_FPU,      dt_tbyte, NULL,   0 },
  { "ST6",    0,                            X86_RC_FPU,      dt_tbyte, NULL,   0 },
  { "ST7",    0,                            X86_RC_FPU,      dt_tbyte, NULL,   0 },
  { "CTRL",   0,                            X86_RC_FPU,      dt_word,  ctrlflags, 0x1F3F },
  { "STAT",   0,                            X86_RC_FPU,      dt_word,  statflags, 0xFFFF },
  { "TAGS",   0,                            X86_RC_FPU,      dt_word,  tagsflags, 0xFFFF },
  // segment registers
  { "CS",     REGISTER_CS|REGISTER_NOLF,    X86_RC_SEGMENTS, dt_word,  NULL,   0 },
  { "DS",     REGISTER_NOLF,                X86_RC_SEGMENTS, dt_word,  NULL,   0 },
  { "ES",     0,                            X86_RC_SEGMENTS, dt_word,  NULL,   0 },
  { "FS",     REGISTER_NOLF,                X86_RC_SEGMENTS, dt_word,  NULL,   0 },
  { "GS",     REGISTER_NOLF,                X86_RC_SEGMENTS, dt_word,  NULL,   0 },
  { "SS",     REGISTER_SS,                  X86_RC_SEGMENTS, dt_word,  NULL,   0 },
  // general registers
#ifdef __EA64__
  { "RAX",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword, NULL,   0 },
  { "RBX",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword, NULL,   0 },
  { "RCX",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword, NULL,   0 },
  { "RDX",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword, NULL,   0 },
  { "RSI",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword, NULL,   0 },
  { "RDI",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword, NULL,   0 },
  { "RBP",    REGISTER_ADDRESS|REGISTER_FP, X86_RC_GENERAL,  dt_qword, NULL,   0 },
  { "RSP",    REGISTER_ADDRESS|REGISTER_SP, X86_RC_GENERAL,  dt_qword, NULL,   0 },
  { "RIP",    REGISTER_ADDRESS|REGISTER_IP, X86_RC_GENERAL,  dt_qword, NULL,   0 },
  { "R8",     REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword, NULL,   0 },
  { "R9",     REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword, NULL,   0 },
  { "R10",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword, NULL,   0 },
  { "R11",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword, NULL,   0 },
  { "R12",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword, NULL,   0 },
  { "R13",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword, NULL,   0 },
  { "R14",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword, NULL,   0 },
  { "R15",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword, NULL,   0 },
#else
  { "EAX",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_dword, NULL,   0 },
  { "EBX",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_dword, NULL,   0 },
  { "ECX",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_dword, NULL,   0 },
  { "EDX",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_dword, NULL,   0 },
  { "ESI",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_dword, NULL,   0 },
  { "EDI",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_dword, NULL,   0 },
  { "EBP",    REGISTER_ADDRESS|REGISTER_FP, X86_RC_GENERAL,  dt_dword, NULL,   0 },
  { "ESP",    REGISTER_ADDRESS|REGISTER_SP, X86_RC_GENERAL,  dt_dword, NULL,   0 },
  { "EIP",    REGISTER_ADDRESS|REGISTER_IP, X86_RC_GENERAL,  dt_dword, NULL,   0 },
#endif
  { "EFL",    0,                            X86_RC_GENERAL,  dt_dword, eflags, 0x00000FD5 }, // OF|DF|IF|TF|SF|ZF|AF|PF|CF
  { "XMM0",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format,  0 },
  { "XMM1",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format,  0 },
  { "XMM2",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format,  0 },
  { "XMM3",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format,  0 },
  { "XMM4",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format,  0 },
  { "XMM5",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format,  0 },
  { "XMM6",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format,  0 },
  { "XMM7",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format,  0 },
#ifdef __EA64__
  { "XMM8",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format,  0 },
  { "XMM9",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format,  0 },
  { "XMM10",  REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format,  0 },
  { "XMM11",  REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format,  0 },
  { "XMM12",  REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format,  0 },
  { "XMM13",  REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format,  0 },
  { "XMM14",  REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format,  0 },
  { "XMM15",  REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format,  0 },
#endif
  { "MXCSR",  0,                            X86_RC_XMM,      dt_dword, mxcsr_bits, 0xFFFF },
  { "MM0",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword, mmx_format,  0 },
  { "MM1",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword, mmx_format,  0 },
  { "MM2",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword, mmx_format,  0 },
  { "MM3",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword, mmx_format,  0 },
  { "MM4",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword, mmx_format,  0 },
  { "MM5",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword, mmx_format,  0 },
  { "MM6",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword, mmx_format,  0 },
  { "MM7",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword, mmx_format,  0 },
};
CASSERT(qnumber(x86_registers) == X86_NREGS);

#ifndef ONLY_REG_DEFS

//--------------------------------------------------------------------------
#if 0
static void DEBUG_REGVALS(regval_t *values)
{
  for (int i = 0; i < qnumber(registers); i++)
  {
    msg("%s = ", registers[i].name);
    switch ( registers[i].dtyp )
    {
      case dt_qword: msg("%016LX\n", values[i].ival); break;
      case dt_dword: msg("%08X\n", values[i].ival); break;
      case dt_word:  msg("%04X\n", values[i].ival); break;
      case dt_tbyte:
      {
        for (int j = 0; j < sizeof(regval_t); j++)
        {
          if ( j == 10) msg(" - " ); // higher bytes are not used by x86 floats
          msg("%02X ", ((unsigned char*)&values[i])[j]);
        }
          // msg("%02X ", (unsigned short)values[i].fval[j]);
        msg("\n");
        break;
      }
    }
  }
  msg("\n");
}
#endif

//--------------------------------------------------------------------------
int idaapi x86_read_registers(thid_t thread_id, int clsmask, regval_t *values)
{
  int code = s_read_registers(thread_id, clsmask, values);
  if ( code > 0 )
  {
    // FPU related registers
    if ( ph.realcvt != NULL && (clsmask & X86_RC_FPU) != 0 )
    {
      for ( int i=R_ST0; i < R_ST0+FPU_REGS_COUNT; i++ )
      {
        if ( ph.realcvt(values[i].fval, values[i].fval, 004) != 0 ) // load long double
          memset(values[i].fval, 0, sizeof(values[i].fval));
      }
    }
  }
  return code;
}

//--------------------------------------------------------------------------
int idaapi x86_write_register(thid_t thread_id, int reg_idx, const regval_t *value)
{
  regval_t rv = *value;
  // FPU related registers
  if ( ph.realcvt != NULL && reg_idx >= R_ST0 && reg_idx < R_ST0+FPU_REGS_COUNT )
  {
    uchar fn[10];
    ph.realcvt(fn, rv.fval, 014); // store long double
    memcpy(rv.fval, fn, 10);
  }
  return s_write_register(thread_id, reg_idx, &rv);
}

//--------------------------------------------------------------------------
int is_x86_valid_bpt(bpttype_t type, ea_t ea, int len)
{
  if ( type != BPT_SOFT )
  {
    if ( type != BPT_RDWR         // type is good?
      && type != BPT_WRITE
      && type != BPT_EXEC)
        return BPT_BAD_TYPE;

    if ( len != 1                 // length is good?
      && (type == BPT_EXEC        // remark: instruction hardware breakpoint only accepts the len of one byte
        || (len != 2 && len != 4)))
          return BPT_BAD_LEN;

    if ( (ea & (len-1)) != 0 )    // alignment is good?
      return BPT_BAD_ALIGN;
  }
  return BPT_OK;
}

#endif

//--------------------------------------------------------------------------
void processor_specific_init(void)
{
}

//--------------------------------------------------------------------------
void processor_specific_term(void)
{
}
