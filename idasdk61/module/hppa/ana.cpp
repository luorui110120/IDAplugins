/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 */

#include "hppa.hpp"

//--------------------------------------------------------------------------
static void simplify(uint32 code)
{
  switch ( cmd.itype )
  {
    // B,L,n target, %r0                =>      B,n    target
    // B,L,n target, %r2                =>      CALL,n target
    case HPPA_b:
      {
        int sub = (code>>13) & 7;
        if ( sub == 1 || sub == 4 ) break;  // ,gate or ,push
        switch ( cmd.Op2.reg )
        {
          case R0:
            cmd.Op2.type = o_void;
            break;
          case R2:
            cmd.itype = HPPA_call;
            cmd.Op2.type = o_void;
            break;
        }
      }
      break;

     // BVE,L,n (b), %r2                =>      CALL,n (b)
     // BVE,n   (%r2)                   =>      RET,n
    case HPPA_bve:
      if ( code & BIT31 ) break;        // ,push or ,pop
      if ( cmd.Op2.type == o_reg )
      {
        cmd.itype = HPPA_call;
        cmd.Op1.type = o_void;
        break;
      }
      if ( cmd.Op1.phrase == R2 )
      {
        cmd.itype = HPPA_ret;
        cmd.Op1.type = o_void;
      }
      break;

    // DEPD,Z,cond r,63-sa,64-sa,t      =>      SHLD,cond r,sa,t
    // DEPW,Z,cond r,31-sa,32-sa,t      =>      SHLW,cond r,sa,t
    case HPPA_depd:
    case HPPA_depw:
      if ( code & BIT21 ) break;        // no Z flag
      if ( cmd.Op2.type == o_imm
        && cmd.Op3.type == o_imm
        && (cmd.Op2.value+1) == cmd.Op3.value )
      {
        cmd.itype    += (HPPA_shld-HPPA_depd);
        cmd.Op2.value = (cmd.itype == HPPA_shld ? 63 : 31) - cmd.Op2.value;
        cmd.Op3       = cmd.Op4;
        cmd.Op4.type  = o_void;
      }
      break;

    // DEPWI,Z,cond -1,31,x,t      =>      LDI,cond (1<<x)-1,t
    case HPPA_depwi:
      if ( code & BIT21 ) break;        // no Z flag
      if ( cmd.Op2.type == o_imm && cmd.Op2.value == 31
        && cmd.Op3.type == o_imm && cmd.Op3.value <= 16 )
      {
        cmd.itype     = HPPA_ldi;
        cmd.Op1.value = (1 << cmd.Op3.value) - 1;
        cmd.Op2       = cmd.Op4;
        cmd.Op3.type  = o_void;
        cmd.Op4.type  = o_void;
      }
      break;
    // EXTRD,S,cond r,63-sa,64-sa,t     =>      SHRD,S,cond r,sa,t
    // EXTRD,U,cond r,63-sa,64-sa,t     =>      SHRD,U,cond r,sa,t
    // EXTRW,S,cond r,31-sa,32-sa,t     =>      SHRW,S,cond r,sa,t
    // EXTRW,U,cond r,31-sa,32-sa,t     =>      SHRW,U,cond r,sa,t
    case HPPA_extrd:
    case HPPA_extrw:
      if ( cmd.Op2.type == o_imm
        && cmd.Op3.type == o_imm
        && (cmd.Op2.value+1) == cmd.Op3.value )
      {
        cmd.itype    += (HPPA_shrd-HPPA_extrd);
        cmd.Op2.value = (cmd.itype == HPPA_shrd ? 63 : 31) - cmd.Op2.value;
        cmd.Op3       = cmd.Op4;
        cmd.Op4.type  = o_void;
      }
      break;

    // LDO i(%r0), t                    =>      LDI i, t
    // LDO 0(r), t                      =>      COPY r, t
    case HPPA_ldo:
      if ( cmd.Op1.reg == R0 )
      {
        cmd.itype = HPPA_ldi;
        cmd.Op1.type = o_imm;
        cmd.Op1.value = cmd.Op1.addr;
        break;
      }
      if ( cmd.Op1.addr == 0 )
      {
        cmd.itype = HPPA_copy;
        cmd.Op1.type = o_reg;
      }
      break;

    // MTCTL r, %sar                    =>      MTSAR r
    case HPPA_mtctl:
      if ( cmd.Op2.reg == CR11 )
      {
        cmd.itype = HPPA_mtsar;
        cmd.Op2.type = o_void;
      }
      break;

    // OR %r0, %r0, %r0                 =>      NOP
    // OR %r, %r0, %t                   =>      COPY r, t
    // OR %r0, %r, %t                   =>      COPY r, t
    case HPPA_or:
      if ( ((code>>13) & 7) ) break;    // condition codes not zero
      if ( cmd.Op1.reg == R0 )
      {
        if ( cmd.Op2.reg == R0 && cmd.Op3.reg == R0 )
        {
          cmd.itype = HPPA_nop;
          cmd.Op1.type = o_void;
          cmd.Op2.type = o_void;
          cmd.Op3.type = o_void;
          break;
        }
        cmd.itype = HPPA_copy;
        cmd.Op1 = cmd.Op2;
        cmd.Op2 = cmd.Op3;
        cmd.Op3.type = o_void;
        break;
      }
      if ( cmd.Op2.reg == R0 )
      {
        cmd.itype = HPPA_copy;
        cmd.Op2 = cmd.Op3;
        cmd.Op3.type = o_void;
      }
      break;
  }
}

//--------------------------------------------------------------------------
struct table1_t
{
  ushort itype;
  char dtyp;
};

static const table1_t C1[] =
{
  { 0,               dt_qword }, // 00
  { 0,               dt_qword }, // 01
  { 0,               dt_qword }, // 02
  { 0,               dt_qword }, // 03
  { 0,               dt_qword }, // 04
  { HPPA_diag,       dt_qword }, // 05
  { HPPA_fmpyadd,    dt_qword }, // 06
  { HPPA_null,       dt_qword }, // 07
  { HPPA_ldil,       dt_qword }, // 08
  { 0,               dt_qword }, // 09
  { HPPA_addil,      dt_qword }, // 0A
  { 0,               dt_qword }, // 0B
  { HPPA_copr,       dt_qword }, // 0C
  { HPPA_ldo,        dt_dword }, // 0D
  { 0,               dt_qword }, // 0E
  { HPPA_null,       dt_qword }, // 0F
  { HPPA_ldb,        dt_byte  }, // 10
  { HPPA_ldh,        dt_word  }, // 11
  { HPPA_ldw,        dt_dword }, // 12
  { HPPA_ldw,        dt_dword }, // 13
  { 0,               dt_qword }, // 14
  { HPPA_null,       dt_dword }, // 15
  { HPPA_fldw,       dt_dword }, // 16
  { 0,               dt_dword }, // 17
  { HPPA_stb,        dt_byte  }, // 18
  { HPPA_sth,        dt_word  }, // 19
  { HPPA_stw,        dt_dword }, // 1A
  { HPPA_stw,        dt_dword }, // 1B
  { 0,               dt_qword }, // 1C
  { HPPA_null,       dt_dword }, // 1D
  { HPPA_fstw,       dt_dword }, // 1E
  { 0,               dt_dword }, // 1F
  { HPPA_cmpb,       dt_byte  }, // 20
  { HPPA_cmpib,      dt_byte  }, // 21
  { HPPA_cmpb,       dt_byte  }, // 22
  { HPPA_cmpib,      dt_dword }, // 23
  { HPPA_cmpiclr,    dt_qword }, // 24
  { HPPA_subi,       dt_dword }, // 25
  { HPPA_fmpysub,    dt_dword }, // 26
  { HPPA_cmpb,       dt_byte  }, // 27
  { HPPA_addb,       dt_byte  }, // 28
  { HPPA_addib,      dt_byte  }, // 29
  { HPPA_addb,       dt_byte  }, // 2A
  { HPPA_addib,      dt_byte  }, // 2B
  { HPPA_addi,       dt_dword }, // 2C
  { HPPA_addi,       dt_dword }, // 2D
  { 0,               dt_dword }, // 2E
  { HPPA_cmpb,       dt_byte  }, // 2F
  { HPPA_bb,         dt_dword }, // 30
  { HPPA_bb,         dt_dword }, // 31
  { HPPA_movb,       dt_byte  }, // 32
  { HPPA_movib,      dt_byte  }, // 33
  { 0,               dt_dword }, // 34
  { 0,               dt_dword }, // 35
  { HPPA_extrd,      dt_qword }, // 36
  { HPPA_null,       dt_dword }, // 37
  { HPPA_be,         dt_dword }, // 38
  { HPPA_be,         dt_dword }, // 39
  { 0,               dt_dword }, // 3A
  { HPPA_cmpib,      dt_byte  }, // 3B
  { 0,               dt_dword }, // 3C
  { 0,               dt_dword }, // 3D
  { 0,               dt_dword }, // 3E
  { HPPA_null,       dt_dword }, // 3F
};

struct ldst_t
{
  ushort itype;
  char dtyp;
};

static const ldst_t C6[] =
{
  { HPPA_ldb,   dt_byte  }, // 0
  { HPPA_ldh,   dt_word  }, // 1
  { HPPA_ldw,   dt_dword }, // 2
  { HPPA_ldd,   dt_qword }, // 3
  { HPPA_ldda,  dt_qword }, // 4
  { HPPA_ldcd,  dt_qword }, // 5
  { HPPA_ldwa,  dt_dword }, // 6
  { HPPA_ldcw,  dt_dword }, // 7
  { HPPA_stb,   dt_byte  }, // 8
  { HPPA_sth,   dt_word  }, // 9
  { HPPA_stw,   dt_dword }, // A
  { HPPA_std,   dt_qword }, // B
  { HPPA_stby,  dt_byte  }, // C
  { HPPA_stdby, dt_qword }, // D
  { HPPA_stwa,  dt_dword }, // E
  { HPPA_stda,  dt_qword }, // F
};

//--------------------------------------------------------------------------
static void opr(op_t &x, uint32 rgnum)
{
  x.reg = (uint16)rgnum;
/*  if ( rgnum == 0 )
  {
    x.type = o_imm;
    x.value = 0;
    x.dtyp = dt_dword;
  }
  else*/
  {
    x.type = o_reg;
    x.dtyp = dt_qword;
  }
}

//--------------------------------------------------------------------------
inline void opi(op_t &x, uval_t v)
{
  x.type = o_imm;
  x.value = v;
  x.dtyp = dt_dword;
}

//--------------------------------------------------------------------------
inline void opb(op_t &x, int r)
{
  x.type   = o_based;
  x.phrase = (uint16)r;
  x.dtyp   = dt_dword;
}

//--------------------------------------------------------------------------
inline void opbs(op_t &x, int sr, int r)
{
  opb(x, r);
  x.sid = uchar(SR0+sr);
  if ( sr != 0 )
    cmd.auxpref |= aux_space;
}

//--------------------------------------------------------------------------
inline void opx(op_t &x, int b, int xx, char dtyp)
{
  x.type   = o_phrase;
  x.phrase = uint16(b);
  x.secreg = uchar(xx);
  x.dtyp   = dtyp;
}

//--------------------------------------------------------------------------
inline void opxs(op_t &x, int sr, int b, int xx, char dtyp)
{
  opx(x, b, xx, dtyp);
  x.sid = uchar(SR0+sr);
  if ( sr != 0 )
    cmd.auxpref |= aux_space;
}

//--------------------------------------------------------------------------
inline void opd(op_t &x, int b, uval_t value, char dtyp)
{
  x.type   = o_displ;
  x.phrase = uint16(b);
  x.addr   = value;
  x.dtyp   = dtyp;
}

//--------------------------------------------------------------------------
inline void opds(op_t &x, int sr, int b, uval_t value, char dtyp)
{
  opd(x, b, value, dtyp);
  x.sid = uchar(SR0+sr);
  if ( sr != 0 )
    cmd.auxpref |= aux_space;
}

//--------------------------------------------------------------------------
struct table_t
{
  char code;
  ushort itype;
};

static const table_t C5[] =
{
  { 0x18,  HPPA_add      },
  { 0x28,  HPPA_add      },
  { 0x38,  HPPA_add      },
  { 0x1C,  HPPA_add      },
  { 0x3C,  HPPA_add      },
  { 0x19,  HPPA_shladd   },
  { 0x29,  HPPA_shladd   },
  { 0x39,  HPPA_shladd   },
  { 0x1A,  HPPA_shladd   },
  { 0x2A,  HPPA_shladd   },
  { 0x3A,  HPPA_shladd   },
  { 0x1B,  HPPA_shladd   },
  { 0x2B,  HPPA_shladd   },
  { 0x3B,  HPPA_shladd   },
  { 0x10,  HPPA_sub      },
  { 0x30,  HPPA_sub      },
  { 0x13,  HPPA_sub      },
  { 0x33,  HPPA_sub      },
  { 0x14,  HPPA_sub      },
  { 0x34,  HPPA_sub      },
  { 0x11,  HPPA_ds       },
  { 0x00,  HPPA_andcm    },
  { 0x08,  HPPA_and      },
  { 0x09,  HPPA_or       },
  { 0x0A,  HPPA_xor      },
  { 0x0E,  HPPA_uxor     },
  { 0x22,  HPPA_cmpclr   },
  { 0x26,  HPPA_uaddcm   },
  { 0x27,  HPPA_uaddcm   },
  { 0x2E,  HPPA_dcor     },
  { 0x2F,  HPPA_dcor     },
  { 0x0F,  HPPA_hadd     },
  { 0x0D,  HPPA_hadd     },
  { 0x0C,  HPPA_hadd     },
  { 0x07,  HPPA_hsub     },
  { 0x05,  HPPA_hsub     },
  { 0x04,  HPPA_hsub     },
  { 0x0B,  HPPA_havg     },
  { 0x1D,  HPPA_hshladd  },
  { 0x1E,  HPPA_hshladd  },
  { 0x1F,  HPPA_hshladd  },
  { 0x15,  HPPA_hshladd  },
  { 0x16,  HPPA_hshladd  },
  { 0x17,  HPPA_hshladd  },
  { 0,     HPPA_null     },
};

static ushort find_itype(const table_t *table, int code)
{
  while ( table->itype )
  {
    if ( table->code == code ) return table->itype;
    table++;
  }
  return HPPA_null;
}

//--------------------------------------------------------------------------
inline sval_t ls5(int i5)   { return (( i5>>1)&15)    | (( i5 & 1) ?    ~sval_t(15) : 0);  }
inline sval_t ls11(int i11) { return ((i11>>1)&0x3FF) | ((i11 & 1) ? ~sval_t(0x1FF) : 0);  }
inline sval_t s12(int imm12){ return (imm12 & 0x0800) ? (imm12 | ~sval_t(0x0FFF)) : imm12; }
inline sval_t s16(int imm16){ return (imm16 & 0x8000) ? (imm16 | ~sval_t(0xFFFF)) : imm16; }
inline sval_t s17(uint32 i17){ return (i17  & 0x10000) ? (i17  | ~sval_t(0x1FFFF)) : i17;   }
inline sval_t s22(uint32 i22){ return (i22 & 0x200000) ? (i22 | ~sval_t(0x3FFFFF)) : i22;   }
inline int mfr(int r, bool d) { return (d ? F0 : F16L) + r; }
inline int as3(int s)
{
  return ((s>>1) & 3) | ((s&1) << 2);
}
inline int fr(int r, int y)
{
  return F0 + r + ((y&1)<<5);
}

//--------------------------------------------------------------------------
static void handle_float_0C(uint32 code)
{
  int uid = (code>> 6) & 7;
  if ( uid == 2 )               // performance coprocessor
  {
    int sub = (code>>9) & 0x1F;
    switch ( sub )
    {
      case 1:
        cmd.itype = HPPA_pmdis;
        break;
      case 3:
        cmd.itype = (code & BIT26) ? HPPA_null : HPPA_pmenb;
        break;
      default:
        cmd.itype = HPPA_null;
        break;
    }
    return;
  }
  if ( uid ) return;            // other coprocessors

  // floating-point coprocessor
  int cls = (code>>9) & 3;
  switch ( cls )
  {
    case 0:
      {
        static const ushort itypes[] =
        {
          HPPA_fid,   HPPA_null, HPPA_fcpy, HPPA_fabs,
          HPPA_fsqrt, HPPA_frnd, HPPA_fneg, HPPA_fnegabs
        };
        cmd.itype = itypes[(code>>13)&7];
        if ( cmd.itype != HPPA_fid )
        {
          opr(cmd.Op1, F0 + r06(code));
          opr(cmd.Op2, F0 + r27(code));
        }
      }
      break;
    case 1:
      cmd.itype = HPPA_fcnv;
      opr(cmd.Op1, F0 + r06(code));
      opr(cmd.Op2, F0 + r27(code));
      break;
    case 2:
      if ( code & BIT26 )
      {
        cmd.itype = HPPA_ftest;
        int y = (code>>13) & 7;
        if ( y != 1 ) opr(cmd.Op1, CA0+(y^1)-1);
      }
      else
      {
        cmd.itype = HPPA_fcmp;
        opr(cmd.Op1, F0 + r06(code));
        opr(cmd.Op2, F0 + r11(code));
        int y = (code>>13) & 7;
        if ( y ) opr(cmd.Op3, CA0+y-1);
      }
      break;
    case 3:
      {
        static const ushort itypes[] =
        {
          HPPA_fadd, HPPA_fsub, HPPA_fmpy, HPPA_fdiv,
          HPPA_frem, HPPA_null, HPPA_null, HPPA_null
        };
        int sub = (code>>13) & 7;
        cmd.itype = (code & BIT26) ? HPPA_null : itypes[sub];
        opr(cmd.Op1, F0 + r06(code));
        opr(cmd.Op2, F0 + r11(code));
        opr(cmd.Op3, F0 + r27(code));
      }
      break;
  }
}

//--------------------------------------------------------------------------
static void handle_float_0E(uint32 code)
{
  int cls = (code>>9) & 3;
  switch ( cls )
  {
    case 0:
      {
        static const ushort itypes[] =
        {
          HPPA_null,  HPPA_null, HPPA_fcpy, HPPA_fabs,
          HPPA_fsqrt, HPPA_frnd, HPPA_fneg, HPPA_fnegabs
        };
        cmd.itype = itypes[(code>>13)&7];
        opr(cmd.Op1, fr(r06(code), (code>>7)&1));
        opr(cmd.Op2, fr(r27(code), (code>>6)&1));
      }
      break;
    case 1:
      cmd.itype = HPPA_fcnv;
      opr(cmd.Op1, fr(r06(code), (code>>7)&1));
      opr(cmd.Op2, fr(r27(code), (code>>6)&1));
      break;
    case 2:
      {
        cmd.itype = HPPA_fcmp;
        opr(cmd.Op1, fr(r06(code), (code>>7)&1));
        opr(cmd.Op2, fr(r11(code), (code>>12)&1));
        int y = (code>>13) & 7;
        if ( y ) opr(cmd.Op3, CA0+y-1);
      }
      break;
    case 3:
      {
        static const ushort itypes[] =
        {
          HPPA_fadd, HPPA_fsub, HPPA_fmpy, HPPA_fdiv,
          HPPA_null, HPPA_null, HPPA_null, HPPA_null
        };
        int sub = (code>>13) & 7;
        cmd.itype = itypes[sub];
        if ( code & BIT23 )
        {
          cmd.itype = (sub == 2) ? HPPA_xmpyu : HPPA_null;
        }
        opr(cmd.Op1, fr(r06(code), (code>>7)&1));
        opr(cmd.Op2, fr(r11(code), (code>>12)&1));
        opr(cmd.Op3, fr(r27(code), (code>>6)&1));
      }
      break;
  }
}

//--------------------------------------------------------------------------
inline void opn(op_t &x, sval_t disp)
{
  disp <<= 2;
  x.type = o_near;
  x.addr = cmd.ip + 8 + disp;
}

//--------------------------------------------------------------------------
int idaapi ana(void)
{
  if ( cmd.ip & 3 ) return 0;           // alignment error

  uint32 code = ua_next_long();

  int op = opcode(code);
  cmd.itype = C1[op].itype;
  char dtyp = C1[op].dtyp;
  switch ( op )
  {
    case 0x00:
      switch ( (code>>5) & 0xFF )
      {
        case 0x00:
          cmd.itype = HPPA_break;
          opi(cmd.Op1, r27(code));
          opi(cmd.Op2, (code>>13) & 0x1FFF);
          break;
        case 0x20:
          cmd.itype = (code & BIT11) ? HPPA_syncdma : HPPA_sync;
          break;
        case 0x60:
        case 0x65:
          cmd.itype = HPPA_rfi;
          break;
        case 0x6B:
          cmd.itype = HPPA_ssm;
RSM_SSM:
          opi(cmd.Op1, (code>>16)&0x3FF);
          opr(cmd.Op2, r27(code));
          break;
        case 0x73:
          cmd.itype = HPPA_rsm;
          goto RSM_SSM;
        case 0xC3:
          cmd.itype = HPPA_mtsm;
          opr(cmd.Op1, r11(code));
          break;
        case 0x85:
          cmd.itype = HPPA_ldsid;
          opbs(cmd.Op1, (code>>14)&3, r06(code));
          opr(cmd.Op2, r27(code));
          break;
        case 0xC1:
          cmd.itype = HPPA_mtsp;
          opr(cmd.Op1, r11(code));
          opr(cmd.Op2, SR0+((code>>13)&7));
          break;
        case 0x25:
          cmd.itype = HPPA_mfsp;
          opr(cmd.Op1, SR0+((code>>13)&7));
          opr(cmd.Op2, r27(code));
          break;
        case 0xA5:
          cmd.itype = HPPA_mfia;
          opr(cmd.Op1, r27(code));
          break;
        case 0xC2:
          cmd.itype = HPPA_mtctl;
          opr(cmd.Op1, r11(code));
          opr(cmd.Op2, CR0+r06(code));
          break;
        case 0xC6:
          if ( r06(code) != 0xB ) return 0;
          cmd.itype = HPPA_mtsarcm;
          opr(cmd.Op1, r11(code));
          break;
        case 0x45:
          cmd.itype = HPPA_mfctl;
          opr(cmd.Op1, CR0+r06(code));
          opr(cmd.Op2, r27(code));
          break;
        default:
          return 0;
      }
      break;

    case 0x01:
      if ( code & BIT19 )
      {
        switch ( (code>>6) & 0xFF )
        {
          case 0x60:
            cmd.itype = HPPA_idtlbt;
            opr(cmd.Op1, CR0+r06(code));
            opr(cmd.Op2, r27(code));
            break;
          case 0x48:
          case 0x58:
            cmd.itype = HPPA_pdtlb;
            goto PDT;
          case 0x49:
            cmd.itype = HPPA_pdtlbe;
PDT:
            opxs(cmd.Op1, (code>>14)&3, r06(code), r11(code), dt_dword);
            break;
          case 0x4A:
            cmd.itype = HPPA_fdc;
            opxs(cmd.Op1, (code>>14)&3, r06(code), r11(code), dt_dword);
            break;
          case 0xCA:
            cmd.itype = HPPA_fdc;
            opds(cmd.Op1, (code>>14)&3, r06(code), ls5(r11(code)), dt_dword);
            if ( code & BIT26 ) return 0;
            break;
          case 0x4B:
            cmd.itype = HPPA_fdce;
            opxs(cmd.Op1, (code>>14)&3, r06(code), r11(code), dt_dword);
            break;
          case 0x4E:
            cmd.itype = HPPA_pdc;
            opxs(cmd.Op1, (code>>14)&3, r06(code), r11(code), dt_dword);
            break;
          case 0x4F:
            cmd.itype = HPPA_fic;
            opxs(cmd.Op1, (code>>14)&3, r06(code), r11(code), dt_dword);
            break;
          case 0x46:
          case 0x47:
            cmd.itype = HPPA_probe;
            opbs(cmd.Op1, (code>>14)&3, r06(code));
            opr(cmd.Op2, r11(code));
            opr(cmd.Op3, r27(code));
            break;
          case 0xC6:
          case 0xC7:
            cmd.itype = HPPA_probei;
            opbs(cmd.Op1, (code>>14)&3, r06(code));
            opi(cmd.Op2, r11(code));
            opr(cmd.Op3, r27(code));
            break;
          case 0x4D:
            cmd.itype = HPPA_lpa;
MAKE_LPA:
            opxs(cmd.Op1, (code>>14)&3, r06(code), r11(code), dt_dword);
            opr(cmd.Op2, r27(code));
            break;
          case 0x4C:
            cmd.itype = HPPA_lci;
            if ( code & BIT26 ) return 0;
            goto MAKE_LPA;
          default:
            return 0;
        }
      }
      else
      {
        switch ( (code>>6) & 0x7F )
        {
          case 0x20:
            cmd.itype = HPPA_iitlbt;
            opr(cmd.Op1, r11(code));
            opr(cmd.Op2, r06(code));
            break;
          case 0x18:
          case 0x08:
            cmd.itype = HPPA_pitlb;
PIT:
            opxs(cmd.Op1, as3((code>>13)&7), r06(code), r11(code), dt_dword);
            cmd.auxpref |= aux_space;
            break;
          case 0x09:
            cmd.itype = HPPA_pitlbe;
            goto PIT;
          case 0x0A:
            cmd.itype = HPPA_fic;
            goto PIT;
          case 0x0B:
            cmd.itype = HPPA_fice;
            goto PIT;
          default:
            return 0;
        }
      }
      break;

    case 0x02:
      cmd.auxpref = (code>>13) & aux_cndc; // condition
      cmd.itype = find_itype(C5, (code>>6)&0x3F);
      switch ( cmd.itype )
      {
        default:
        //case HPPA_add:
        //case HPPA_sub:
        //case HPPA_ds:
        //case HPPA_and:
        //case HPPA_andcm:
        //case HPPA_or:
        //case HPPA_xor:
        //case HPPA_uxor:
        //case HPPA_cmpclr:
        //case HPPA_uaddcm:
        //case HPPA_hadd:
        //case HPPA_hsub:
        //case HPPA_havg:
          opr(cmd.Op1, r11(code));
          opr(cmd.Op2, r06(code));
          opr(cmd.Op3, r27(code));
          break;
        case HPPA_dcor:
          opr(cmd.Op1, r06(code));
          opr(cmd.Op2, r27(code));
          break;
        case HPPA_shladd:
          opr(cmd.Op1, r11(code));
          opi(cmd.Op2, (code>>6)&3);
          if ( ((code>>6) & 3) == 0 ) return 0;
          opr(cmd.Op3, r06(code));
          opr(cmd.Op4, r27(code));
          break;
        case HPPA_hshladd:
          opr(cmd.Op1, r11(code));
          opr(cmd.Op2, r06(code));
          if ( ((code>>6) & 3) == 0 ) return 0;
          if ( cmd.auxpref ) return 0;  // condition should be never
          opi(cmd.Op3, (code>>6)&3);
          opr(cmd.Op4, r27(code));
          break;
      }
      break;

    case 0x03:
      {
        int idx = (code>>6) & 0xF;
        if ( (code & BIT19) == 0 && idx > 7 ) return 0;
        cmd.itype = C6[idx].itype;
        char dtyp = C6[idx].dtyp;
        if ( code & BIT19 )             // short
        {
          if ( idx > 7 )        // store
          {
            opr(cmd.Op1, r11(code));
            opds(cmd.Op2, (code>>14)&3, r06(code), ls5(r27(code)), dtyp);
          }
          else                  // load
          {
            opds(cmd.Op1, (code>>14)&3, r06(code), ls5(r11(code)), dtyp);
            opr(cmd.Op2, r27(code));
          }
        }
        else                            // index
        {
          opxs(cmd.Op1, (code>>14)&3, r06(code), r11(code), dtyp);
          opr(cmd.Op2, r27(code));
        }
        if ( (idx & 7) == 6 ) cmd.auxpref &= ~aux_space; // ldwa, stwa
      }
      break;

    case 0x04:
      switch ( (code>>9) & 3 )
      {
        case 0:
          cmd.itype = HPPA_spop0;
          break;
        case 1:
          cmd.itype = HPPA_spop1;
          opr(cmd.Op1, r27(code));
          break;
        case 2:
          cmd.itype = HPPA_spop2;
          opr(cmd.Op1, r06(code));
          break;
        case 3:
          cmd.itype = HPPA_spop3;
          opr(cmd.Op1, r11(code));
          opr(cmd.Op2, r06(code));
          break;
      }
      break;

    case 0x05:  // diag
      opi(cmd.Op1, code & 0x3FFFFFF);
      break;

    case 0x06:  // fmpyadd
    case 0x26:  // fmpysub
      {
        bool d = !((code>>5) & 1);
        opr(cmd.Op1, mfr(r06(code),d));
        opr(cmd.Op2, mfr(r11(code),d));
        opr(cmd.Op3, mfr(r27(code),d));
        opr(cmd.Op4, mfr((code>>6)&0x1F,d));
        opr(cmd.Op5, mfr((code>>11)&0x1F,d));
      }
      break;

    case 0x07:
      return 0;

    case 0x08:  // ldil
      opi(cmd.Op1, as21(code & 0x1FFFFF));
      opr(cmd.Op2, r06(code));
      break;

    case 0x09: // cldw, cstw, fstd, fstw
    case 0x0B: // cldd, cstd, fldd, fldw
      {
        op_t *x;
        int uid = (code>> 6) & 7;
        if ( code & BIT22 )
        {
          cmd.itype = HPPA_cstd;
          opr(cmd.Op1, r27(code));
          x = &cmd.Op2;
          if ( uid < 2 )
          {
            cmd.itype = HPPA_fstd;
            cmd.Op1.reg += F0 + ((code>>1)&0x20);
          }
        }
        else
        {
          cmd.itype = HPPA_cldd;
          opr(cmd.Op2, r27(code));
          x = &cmd.Op1;
          if ( uid < 2 )
          {
            cmd.itype = HPPA_fldd;
            cmd.Op2.reg += F0 + ((code>>1)&0x20);
          }
        }
        char dtyp = dt_qword;
        if ( op == 0x09 )
        {
          cmd.itype++; // cldw, cstw
          dtyp = dt_dword;
        }
        if ( code & BIT19 )
          opds(*x, (code>>14)&3, r06(code), ls5(r11(code)), dtyp);
        else
          opxs(*x, (code>>14)&3, r06(code), r11(code), dtyp);
      }
      break;

    case 0x0A:  // addil
      opi(cmd.Op1, as21(code & 0x1FFFFF));
      opr(cmd.Op2, r06(code));
      opr(cmd.Op3, R1);
      break;

    case 0x0C:  // copr
      handle_float_0C(code);
      break;

    case 0x0D:  // ldo
      if ( getseg(cmd.ea)->use64() )
        dtyp = dt_qword;
      opd(cmd.Op1, r06(code), s16(get_ldo(code)), dtyp);
      opr(cmd.Op2, r11(code));
      break;

    case 0x0E:
      handle_float_0E(code);
      break;

    case 0x0F:
      return 0;

    case 0x10:  // ldb
    case 0x11:  // ldh
    case 0x12:  // ldw
    case 0x13:  // ldw (mod)
      {
        int s = (code>>14) & 3;
        opds(cmd.Op1, s, r06(code), s16(assemble_16(s,code & 0x3FFF)), dtyp);
        opr(cmd.Op2, r11(code));
      }
      break;

    case 0x14:
      {
        int s = (code>>14) & 3;
        cmd.itype = (code & BIT30) ? HPPA_fldd : HPPA_ldd;
        int im10a = ((code>>3) & 0x7FE) | (code & 1);
        opds(cmd.Op1, s, r06(code), s16(assemble_16(s,im10a)), dtyp);
        opr(cmd.Op2, r11(code));
        if ( code & BIT30 ) cmd.Op2.reg += F0;
      }
      break;

    case 0x1C:
      {
        int s = (code>>14) & 3;
        cmd.itype = (code & BIT30) ? HPPA_fstd : HPPA_std;
        int im10a = ((code>>3) & 0x7FE) | (code & 1);
        opr(cmd.Op1, r11(code));
        if ( code & BIT30 ) cmd.Op1.reg += F0;
        opds(cmd.Op2, s, r06(code), s16(assemble_16(s,im10a)), dtyp);
      }
      break;

    case 0x16:
    case 0x17:
      {
        int s = (code>>14) & 3;
        cmd.itype = op & 1 && (code & BIT29) ? HPPA_ldw : HPPA_fldw;
        int im11a = ((code>>3) & 0xFFE) | (code & 1);
        opds(cmd.Op1, s, r06(code), s16(assemble_16(s,im11a)), dtyp);
        opr(cmd.Op2, r11(code));
        if ( code & BIT29 ) cmd.Op2.reg += F0 + ((code<<4) & 0x20);
      }
      break;

    case 0x1E:
    case 0x1F:
      {
        int s = (code>>14) & 3;
        cmd.itype = op & 1 && (code & BIT29) ? HPPA_stw : HPPA_fstw;
        int im11a = ((code>>3) & 0xFFE) | (code & 1);
        opr(cmd.Op1, r11(code));
        if ( code & BIT29 ) cmd.Op1.reg += F0 + ((code<<4) & 0x20);
        opds(cmd.Op2, s, r06(code), s16(assemble_16(s,im11a)), dtyp);
      }
      break;

    case 0x18:  // stb
    case 0x19:  // sth
    case 0x1A:  // stw
    case 0x1B:  // stw (mod)
      {
        int s = (code>>14) & 3;
        opr(cmd.Op1, r11(code));
        opds(cmd.Op2, s, r06(code), s16(assemble_16(s,code & 0x3FFF)), dtyp);
      }
      break;

    case 0x15:
    case 0x1D:
      return 0;

    case 0x20:  // cmpb
    case 0x22:  // cmpb
    case 0x27:  // cmpb
    case 0x2F:  // cmpb
    case 0x28:  // addb
    case 0x2A:  // addb
    case 0x32:  // movb
      cmd.auxpref = (code>>13) & aux_cndc; // condition
      opr(cmd.Op1, r11(code));
      opr(cmd.Op2, r06(code));
      opn(cmd.Op3, s12(get11(code)|((code&1)<<11)));
      break;

    case 0x21:  // cmpib
    case 0x23:  // cmpib
    case 0x3B:  // cmpib
    case 0x29:  // addib
    case 0x2B:  // addib
    case 0x33:  // movib
      cmd.auxpref = (code>>13) & aux_cndc; // condition
      opi(cmd.Op1, ls5(r11(code)));
      opr(cmd.Op2, r06(code));
      opn(cmd.Op3, s12(get11(code)|((code&1)<<11)));
      break;

    case 0x24:  // cmpiclr
    case 0x25:  // subi
    case 0x2C:  // addi
    case 0x2D:  // addi
      cmd.auxpref = (code>>13) & aux_cndc; // condition
      opi(cmd.Op1, ls11(code & 0x7FF));
      opr(cmd.Op2, r06(code));
      opr(cmd.Op3, r11(code));
      break;

    case 0x2E:
      {
        cmd.itype = (code & BIT26) ? HPPA_fmpynfadd : HPPA_fmpyfadd;
        bool d = (code>>11) & 1;
        opr(cmd.Op1, mfr(r06(code),d));
        opr(cmd.Op2, mfr(r11(code),d));
        int ra = ((code>>10) & 0x38) | ((code>>8) & 0x7);
        opr(cmd.Op3, F0+ra);
        opr(cmd.Op4, mfr(r27(code),d));
      }
      break;

    case 0x30:  // bb
    case 0x31:
      opr(cmd.Op1, r11(code));
      if ( op & 1 )
      {
        int pos = r06(code) | ((code>>8) & 0x20);
        opi(cmd.Op2, pos);
      }
      else
      {
        opr(cmd.Op2, CR11);
      }
      opn(cmd.Op3, s12(get11(code)|((code&1)<<11)));
      break;

    case 0x34:
      cmd.auxpref = (code>>13) & aux_cndc; // condition
      switch ( (code>>11) & 3 )     // bits 19, 20
      {
        case 0:
          if ( (code & BIT21) == 0 )            // format 11
          {
            cmd.itype = (code & BIT22) ? HPPA_shrpd : HPPA_shrpw;
            opr(cmd.Op1, r11(code));
            opr(cmd.Op2, r06(code));
            opr(cmd.Op3, CR11);
            opr(cmd.Op4, r27(code));
            break;
          }
          // no break
        case 1:                                 // format 14
          {
            cmd.itype = (code & BIT21) ? HPPA_shrpd : HPPA_shrpw;
            opr(cmd.Op1, r11(code));
            opr(cmd.Op2, r06(code));
            int sa = (cmd.itype == HPPA_shrpd ? 63 : 31) - (r22(code)|((code>>10)&1));
            opi(cmd.Op3, sa);
            opr(cmd.Op4, r27(code));
          }
          break;
        case 2:                                 // format 12
          {
            cmd.itype = (code & BIT22) ? HPPA_extrd : HPPA_extrw;
            opr(cmd.Op1, r06(code));
            opr(cmd.Op2, CR11);
            int cl = (code>>3) & 0x20;
            if ( (code & BIT22) == 0 && cl ) return 0;
            opi(cmd.Op3, (32-r27(code))|cl);
            opr(cmd.Op4, r11(code));
          }
          break;
        case 3:                                 // format 15
          cmd.itype = HPPA_extrw;
          opr(cmd.Op1, r06(code));
          opi(cmd.Op2, r22(code));
          opi(cmd.Op3, 32-r27(code));
          opr(cmd.Op4, r11(code));
          break;
      }
      break;

    case 0x35:
      cmd.auxpref = (code>>13) & aux_cndc; // condition
      if ( code & BIT20 )                       // format 16
      {
        if ( code & BIT19 )
        {
          cmd.itype = HPPA_depwi;
          opi(cmd.Op1, ls5(r11(code)));
        }
        else
        {
          cmd.itype = HPPA_depw;
          opr(cmd.Op1, r11(code));
        }
        opi(cmd.Op2, 31-r22(code));
        opi(cmd.Op3, 32-r27(code));
        opr(cmd.Op4, r06(code));
      }
      else                                      // format 13
      {
        if ( code & BIT19 )
        {
          cmd.itype = (code & BIT22) ? HPPA_depdi : HPPA_depwi;
          opi(cmd.Op1, ls5(r11(code)));
          opr(cmd.Op2, CR11);
        }
        else
        {
          cmd.itype = (code & BIT22) ? HPPA_depd : HPPA_depw;
          opr(cmd.Op1, r11(code));
          opr(cmd.Op2, CR11);
        }
        int cl = (code>>3) & 0x20;
        if ( (code & BIT22) == 0 && cl ) return 0;
        opi(cmd.Op3, (32-r27(code))|cl);
        opr(cmd.Op4, r06(code));
      }
      break;

    case 0x36:  // extrd
      {
        cmd.auxpref = (code>>13) & aux_cndc; // condition
        opr(cmd.Op1, r06(code));
        opi(cmd.Op2, ((code>>6)&0x20)|r22(code));
        int cl = (code>>7) & 0x20;
        opi(cmd.Op3, (32-r27(code))|cl);
        opr(cmd.Op4, r11(code));
      }
      break;

    case 0x37:
      return 0;

    case 0x38:  // be
    case 0x39:  // be
      {
        int32 w = get17(code);
        opds(cmd.Op1, as3((code>>13)&7), r06(code), s17(w)<<2, dt_code);
        cmd.auxpref |= aux_space;
        if ( op & 1 )
        {
          opr(cmd.Op2, SR0);
          opr(cmd.Op3, R31);
        }
      }
      break;

    case 0x3A:
      {
        int sub = (code>>13) & 7;
        switch ( sub )
        {
          case 0x2:
            if ( code & BIT19 ) return 0;
            cmd.itype = HPPA_blr;
            opr(cmd.Op1, r11(code));
            opr(cmd.Op2, r06(code));
            break;
          case 0x6:
            cmd.itype = (code & BIT19) ? HPPA_bve : HPPA_bv;
            if ( cmd.itype == HPPA_bv )
              opx(cmd.Op1, r06(code), r11(code), dt_code);
            else
              opb(cmd.Op1, r06(code));
            break;
          case 0x7:
            if ( !(code & BIT19) ) return 0;
            cmd.itype = HPPA_bve;
            opb(cmd.Op1, r06(code));
            opr(cmd.Op1, R2);
            break;
          case 0x0:
          case 0x1:
            {
              cmd.itype = HPPA_b;
              int32 w = get17(code);
              opn(cmd.Op1, s17(w));
              opr(cmd.Op2, r06(code));
            }
            break;
          case 0x4:
          case 0x5:
            {
              cmd.itype = HPPA_b;
              int32 w = ((code&1) << 21)
                     | (r06(code) << 16)
                     | (r11(code) << 11)
                     | get11(code);
              opn(cmd.Op1, s22(w));
              opr(cmd.Op2, R2);
            }
            break;
        }
      }
      break;

    case 0x3C:
      cmd.itype = HPPA_depd;
      opr(cmd.Op1, r11(code));
DEPD:
      opi(cmd.Op2, (32-r22(code))|((code>>7)&0x20));
      opi(cmd.Op3, r27(code));
      opr(cmd.Op4, r06(code));
      cmd.auxpref = (code>>13) & aux_cndc; // condition
      break;

    case 0x3D:
      cmd.itype = HPPA_depdi;
      opi(cmd.Op1, ls5(r11(code)));
      goto DEPD;

    case 0x3E:
      if ( code & BIT16 )
      {
        switch ( (code>>10) & 3 )
        {
          case 0:
            cmd.itype = HPPA_mixw;
            opr(cmd.Op1, r11(code));
            opr(cmd.Op2, r06(code));
            opr(cmd.Op3, r27(code));
            break;
          case 1:
            cmd.itype = HPPA_mixh;
            opr(cmd.Op1, r11(code));
            opr(cmd.Op2, r06(code));
            opr(cmd.Op3, r27(code));
            break;
          case 2:
            if ( ((code>>13)&3) == 0 )
            {
              cmd.itype = HPPA_hshl;
              opr(cmd.Op1, r11(code));
              opi(cmd.Op2, (code>>6) & 0xF);
              opr(cmd.Op3, r27(code));
              break;
            }
            // no break;
          case 3:
            cmd.itype = HPPA_hshr;
            opr(cmd.Op1, r06(code));
            opi(cmd.Op2, (code>>6) & 0xF);
            opr(cmd.Op3, r27(code));
            break;
          default:
            return 0;
        }
      }
      else
      {
        cmd.itype = HPPA_permh;
        if ( r06(code) != r11(code) ) return 0;
        opr(cmd.Op1, r06(code));
        opr(cmd.Op2, r27(code));
      }
      break;

    case 0x3F:
      return 0;

    default:
      interr("ana");
  }
  if ( !cmd.itype ) return 0;
  if ( dosimple() ) simplify(code);
  char buf[80];
  if ( !build_insn_completer(code, buf, sizeof(buf)) ) return 0;
  return cmd.size;
}

//--------------------------------------------------------------------------
void interr(const char *module)
{
  const char *name = NULL;
  if ( cmd.itype < HPPA_last )
    name = Instructions[cmd.itype].name;
  else
    cmd.itype = HPPA_null;
  warning("%a(%s): internal error in %s", cmd.ea, name, module);
}

