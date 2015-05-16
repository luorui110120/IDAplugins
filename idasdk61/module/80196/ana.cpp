/*
 *  Interactive disassembler (IDA).
 *  Intel 80196 module
 *
 *      18.06.99 ig: fixed bug with tijmp
 *
 */

#include "i196.hpp"
#include "ins.hpp"

//----------------------------------------------------------------------
inline uint32 truncate(ea_t x)
{
  return x & (extended ? 0xFFFFF : 0xFFFF);
}

//----------------------------------------------------------------------
struct wsr_mapping_t
{
  uchar wsr;
  ushort base;
  uchar wsrbase;
  uchar wsr1base;
};

static wsr_mapping_t mappings[] =
{
  { 0x10, 0x0000, 0x80, 0xFF },        // 0080-00FF
  { 0x11, 0x0080, 0x80, 0xFF },
  { 0x12, 0x0100, 0x80, 0xFF },
  { 0x13, 0x0180, 0x80, 0xFF },
  { 0x14, 0x0200, 0x80, 0xFF },
  { 0x15, 0x0280, 0x80, 0xFF },
  { 0x16, 0x0300, 0x80, 0xFF },
  { 0x17, 0x0380, 0x80, 0xFF },
  { 0x1E, 0x1F00, 0x80, 0xFF },
  { 0x1F, 0x1F80, 0x80, 0xFF },
  { 0x20, 0x0000, 0xC0, 0x40 },        // 00C0-00FF or 0040-007F
  { 0x21, 0x0040, 0xC0, 0x40 },
  { 0x22, 0x0080, 0xC0, 0x40 },
  { 0x23, 0x00C0, 0xC0, 0x40 },
  { 0x24, 0x0100, 0xC0, 0x40 },
  { 0x25, 0x0140, 0xC0, 0x40 },
  { 0x26, 0x0180, 0xC0, 0x40 },
  { 0x27, 0x01C0, 0xC0, 0x40 },
  { 0x28, 0x0200, 0xC0, 0x40 },
  { 0x29, 0x0240, 0xC0, 0x40 },
  { 0x2A, 0x0280, 0xC0, 0x40 },
  { 0x2B, 0x02C0, 0xC0, 0x40 },
  { 0x2C, 0x0300, 0xC0, 0x40 },
  { 0x2D, 0x0340, 0xC0, 0x40 },
  { 0x2E, 0x0380, 0xC0, 0x40 },
  { 0x2F, 0x03C0, 0xC0, 0x40 },
  { 0x3C, 0x1F00, 0xC0, 0x40 },
  { 0x3D, 0x1F40, 0xC0, 0x40 },
  { 0x3E, 0x1F80, 0xC0, 0x40 },
  { 0x3F, 0x1FC0, 0xC0, 0x40 },
  { 0x40, 0x0000, 0xE0, 0x60 },        // 00E0-00FF or 0060-007F
  { 0x41, 0x0020, 0xE0, 0x60 },
  { 0x42, 0x0040, 0xE0, 0x60 },
  { 0x43, 0x0060, 0xE0, 0x60 },
  { 0x44, 0x0080, 0xE0, 0x60 },
  { 0x45, 0x00A0, 0xE0, 0x60 },
  { 0x46, 0x00C0, 0xE0, 0x60 },
  { 0x47, 0x00E0, 0xE0, 0x60 },
  { 0x48, 0x0100, 0xE0, 0x60 },
  { 0x49, 0x0120, 0xE0, 0x60 },
  { 0x4A, 0x0140, 0xE0, 0x60 },
  { 0x4B, 0x0160, 0xE0, 0x60 },
  { 0x4C, 0x0180, 0xE0, 0x60 },
  { 0x4D, 0x01A0, 0xE0, 0x60 },
  { 0x4E, 0x01C0, 0xE0, 0x60 },
  { 0x4F, 0x01E0, 0xE0, 0x60 },
  { 0x50, 0x0200, 0xE0, 0x60 },
  { 0x51, 0x0220, 0xE0, 0x60 },
  { 0x52, 0x0240, 0xE0, 0x60 },
  { 0x53, 0x0260, 0xE0, 0x60 },
  { 0x54, 0x0280, 0xE0, 0x60 },
  { 0x55, 0x02A0, 0xE0, 0x60 },
  { 0x56, 0x02C0, 0xE0, 0x60 },
  { 0x57, 0x02E0, 0xE0, 0x60 },
  { 0x58, 0x0300, 0xE0, 0x60 },
  { 0x59, 0x0320, 0xE0, 0x60 },
  { 0x5A, 0x0340, 0xE0, 0x60 },
  { 0x5B, 0x0360, 0xE0, 0x60 },
  { 0x5C, 0x0380, 0xE0, 0x60 },
  { 0x5D, 0x03A0, 0xE0, 0x60 },
  { 0x5E, 0x03C0, 0xE0, 0x60 },
  { 0x5F, 0x03E0, 0xE0, 0x60 },
  { 0x78, 0x1F00, 0xE0, 0x60 },
  { 0x79, 0x1F20, 0xE0, 0x60 },
  { 0x7A, 0x1F40, 0xE0, 0x60 },
  { 0x7B, 0x1F60, 0xE0, 0x60 },
  { 0x7C, 0x1F80, 0xE0, 0x60 },
  { 0x7D, 0x1FA0, 0xE0, 0x60 },
  { 0x7E, 0x1FC0, 0xE0, 0x60 },
  { 0x7F, 0x1FE0, 0xE0, 0x60 },
};

static int NT_CDECL cmp(const void *x, const void *y)
{
  const wsr_mapping_t *a = (const wsr_mapping_t *)x;
  const wsr_mapping_t *b = (const wsr_mapping_t *)y;
  return a->wsr - b->wsr;
}

//----------------------------------------------------------------------
// perform WSR/WSR1 mapping
static ea_t map(ea_t v)
{
  if ( !extended ) return v;
  if ( v < 0x40 ) return v;
  sel_t wsr = getSR(cmd.ea, v < 0x80 ? WSR1 : WSR) & 0x7F;
  if ( wsr < 0x10 ) return v;

  wsr_mapping_t key;
  key.wsr = (char)wsr;
  wsr_mapping_t *p = (wsr_mapping_t *)
                bsearch(&key, mappings, qnumber(mappings), sizeof(key), cmp);
  if ( p == NULL ) return v;

  int delta = v < 0x80 ? p->wsr1base : p->wsrbase;
  if ( v < delta ) return v;
  return v - delta + p->base;
}

//----------------------------------------------------------------------
static void aop( uint code, op_t &op )
{
  switch( code & 3 )
  {
    case 0:   // direct
      op.type = o_mem;
      op.addr = map(ua_next_byte());
      break;

    case 1:   // immediate
      op.type = o_imm;
      if( (code & 0x10) == 0 && (code & 0xFC) != 0xAC ) // ldbze always baop
      {
        op.dtyp  = dt_word;
        op.value = ua_next_word();
      }
      else
        op.value = ua_next_byte();
      break;

    case 2:   // indirect
      op.dtyp = dt_word;
      op.addr = ua_next_byte();
      op.type = (op.addr & 1) ? o_indirect_inc : o_indirect;
      op.addr = map(op.addr & ~1);
      break;

    case 3:   // indexed
      op.dtyp  = dt_word;
      op.type  = o_indexed;
      op.value = ua_next_byte();   // short (reg file)
      op.addr  = (op.value & 1) ? ua_next_word() : ua_next_byte();
      op.value = map(op.value & ~1);
  }
}

//----------------------------------------------------------------------
static int ld_st(ushort itype, char dtyp, bool indirect, op_t &reg, op_t &mem)
{
  if ( !extended ) return 0;
  cmd.itype = itype;
  reg.dtyp  = dtyp;
  mem.dtyp  = dtyp;
  mem.addr  = ua_next_byte();
  if ( indirect ) // indirect
  {
    mem.type = (mem.addr & 1) ? o_indirect_inc : o_indirect;
    mem.addr = map(mem.addr & ~1);
  }
  else
  {
    mem.type  = o_indexed;
    mem.value = map(mem.addr);
    mem.addr  = ua_next_word();
    mem.addr |= ua_next_byte() << 16;
  }
  reg.type = o_mem;
  reg.addr = map(ua_next_byte());
  return cmd.size;
}

//----------------------------------------------------------------------

int idaapi ana( void )
{
  cmd.Op1.dtyp = dt_byte;
  cmd.Op2.dtyp = dt_byte;
  cmd.Op3.dtyp = dt_byte;

  uint code = ua_next_byte();

  uint nibble0 = (code & 0xF);
  uint nibble1 = (code >> 4);

  char offc;
  int32 off;
  uint tmp;

  if( nibble1 < 2 )   // 0,1
  {
    static const char cmd01[] =
    {
      I196_skip, I196_clr,  I196_not,   I196_neg,
      I196_xch,  I196_dec,  I196_ext,   I196_inc,
      I196_shr,  I196_shl,  I196_shra,  I196_xch,
      I196_shrl, I196_shll, I196_shral, I196_norml,
      I196_null, I196_clrb, I196_notb,  I196_negb,
      I196_xchb, I196_decb, I196_extb,  I196_incb,
      I196_shrb, I196_shlb, I196_shrab, I196_xchb,
      I196_est,  I196_est,  I196_estb,  I196_estb
    };

    cmd.itype = cmd01[code & 0x1F];

    if( cmd.itype == I196_null )    return 0;   // unknown command

    switch( code )
    {
      case 0x4: case 0x14:  //xch reg,aop        direct
      case 0xB: case 0x1B:  //xch reg,aop        indexed
        if( (code & 0x10) == 0 )    cmd.Op2.dtyp = dt_word;
        aop( code, cmd.Op2 );
        cmd.Op1.addr = map(ua_next_byte());
        cmd.Op1.type = o_mem;
        break;

      case 0xF:             //norml lreg,breg
        cmd.Op2.addr = map(ua_next_byte());
        cmd.Op2.type = o_mem;
        cmd.Op1.addr = map(ua_next_byte());
        cmd.Op1.type = o_mem;
        break;

      case 0x1C:                 // est.indirect
      case 0x1D:                 // est.indexed
        return ld_st(I196_est, dt_word, code == 0x1C, cmd.Op1, cmd.Op2);

      case 0x1E:                 // estb.indirect
      case 0x1F:                 // estb.indexed
        return ld_st(I196_estb, dt_byte, code == 0x1E, cmd.Op1, cmd.Op2);

      default:              // shifts
        tmp = ua_next_byte();
        if( tmp < 16 )
        {
          cmd.Op2.value = tmp;
          cmd.Op2.type  = o_imm;
        }
        else
        {
          cmd.Op2.addr  = map(tmp);
          cmd.Op2.type  = o_mem;
        }

      case 0x0:  case 0x1:  case 0x2:  case 0x3:
      case 0x5:  case 0x6:  case 0x7:  case 0x11:
      case 0x12: case 0x13: case 0x15: case 0x16: case 0x17:
        cmd.Op1.addr  = map(ua_next_byte());
        cmd.Op1.type  = o_mem;
    }

    switch( code )
    {
      case 0x1:  case 0x2:  case 0x3:  case 0x4:  case 0x5:
      case 0x7:  case 0x8:  case 0x9:  case 0xA:  case 0xB:  case 0x16:
        cmd.Op1.dtyp  = dt_word;
        break;

      case 0x6:  case 0xC:  case 0xD:  case 0xE:  case 0xF:
        cmd.Op1.dtyp  = dt_dword;
    }
  }
  else if( nibble1 < 4 )    // 2,3
  {
    static const char cmd23[] = { I196_sjmp, I196_scall, I196_jbc, I196_jbs };

    cmd.itype = cmd23[ (code - 0x20) >> 3 ];

    if( nibble1 == 2 )      // sjmp/scall
    {
      cmd.Op1.type = o_near;
      off = ua_next_byte() + ((code & 7) << 8);
      if( off & 0x400 ) off |= ~0x7FF;  else off &= 0x7FF;  // make signed
      cmd.Op1.addr = truncate(cmd.ip + cmd.size + off);     // signed addition
//      cmd.Op1.dtyp = dt_word;
    }
    else                    // jbc/jbs
    {
      cmd.Op2.type = o_bit;
      cmd.Op2.reg  = code & 7;
      cmd.Op1.addr = map(ua_next_byte());
      cmd.Op1.type = o_mem;
      cmd.Op3.type = o_near;
      offc = ua_next_byte();
      cmd.Op3.addr = truncate(cmd.ip + cmd.size + offc);      // signed addition
//      cmd.Op3.dtyp = dt_word;
    }
  }
  else if( nibble1 < 6 )    // 4,5
  {
    static const char cmd45[] =
    {
      I196_and3,  I196_add3,  I196_sub3,  I196_mulu3,
      I196_andb3, I196_addb3, I196_subb3, I196_mulub3
    };

    cmd.itype = cmd45[ (code - 0x40) >> 2 ];

    if( (code & 0x10) == 0 )
      cmd.Op1.dtyp = cmd.Op2.dtyp = cmd.Op3.dtyp = dt_word;

    if( (code & 0xc) == 0xc )   // mulu/mulub
      cmd.Op1.dtyp++;           // word->dword/byte->word

    aop( code, cmd.Op3 );
    cmd.Op2.addr  = map(ua_next_byte());
    cmd.Op2.type  = o_mem;
    cmd.Op1.addr  = map(ua_next_byte());
    cmd.Op1.type  = o_mem;
  }
  else if( nibble1 < 0xD )    // 6,7,8,9,A,B,C
  {
    static const char cmd6c[] =
    {
      I196_and2,  I196_add2,   I196_sub2,   I196_mulu2,
      I196_andb2, I196_addb2,  I196_subb2,  I196_mulub2,
      I196_or,    I196_xor,    I196_cmp,    I196_divu,
      I196_orb,   I196_xorb,   I196_cmpb,   I196_divub,
      I196_ld,    I196_addc,   I196_subc,   I196_ldbze,
      I196_ldb,   I196_addcb,  I196_subcb,  I196_ldbse,
      I196_st,    I196_stb,    I196_push,   I196_pop
    };

    cmd.itype = cmd6c[ (code - 0x60) >> 2 ];

    switch( nibble1 )
    {
      case 6:     // and/add/sub/mulu
      case 8:     // or/xor/cmp/duvu
        cmd.Op1.dtyp = cmd.Op2.dtyp = dt_word;
        if( (nibble0 & 0xC) == 0xC )  cmd.Op1.dtyp++;   //mulu/divu
        break;

      case 0xA:   // ld/addc/subc/ldbze
        cmd.Op1.dtyp = cmd.Op2.dtyp = dt_word;
        if( (nibble0 & 0xC) == 0xC )  cmd.Op2.dtyp = dt_byte;   //ldbze
        break;
    }

    switch( code & 0xFC )
    {
      case 0xC0:    // st
        cmd.Op2.dtyp = dt_word;

      case 0x7C: case 0x9C: case 0xBC: case 0xC8: case 0xCC:
        cmd.Op1.dtyp = dt_word;
    }

    switch( code )
    {
      case 0xC1:
        cmd.itype    = I196_bmov;
        goto cont1;

      case 0xC5:
        cmd.itype    = I196_cmpl;
        cmd.Op2.dtyp = dt_dword;
        goto cont2;

      case 0xCD:
        cmd.itype    = I196_bmovi;
cont1:
        cmd.Op2.dtyp = dt_word;
cont2:
        cmd.Op2.addr = map(ua_next_byte());
        cmd.Op2.type = o_mem;
        cmd.Op1.dtyp = dt_dword;
//        cmd.Op1.addr = ua_next_byte();
//        cmd.Op1.type = o_mem;
        goto cont3;

      default:
        if( code > 0xC7 )
          aop( code, cmd.Op1 );
        else
        {
          aop( code, cmd.Op2 );
cont3:
          cmd.Op1.addr  = map(ua_next_byte());
          cmd.Op1.type  = o_mem;
        }
    }
  }
  else if( nibble1 == 0xD )     // jcc
  {
    static const char cmdd[] =
    {
      I196_jnst, I196_jnh, I196_jgt, I196_jnc,
      I196_jnvt, I196_jnv, I196_jge, I196_jne,
      I196_jst,  I196_jh,  I196_jle, I196_jc,
      I196_jvt,  I196_jv,  I196_jlt, I196_je
    };

    cmd.itype = cmdd[nibble0];

    cmd.Op1.type = o_near;
    offc = ua_next_byte();
    cmd.Op1.addr = truncate(cmd.ip + cmd.size + offc);      // signed addition
//    cmd.Op1.dtyp = dt_word;
  }
  else if( nibble1 == 0xE )     // Ex
  {
    switch( nibble0 )
    {
      case 0x0: case 0x1:       // djnz, djnzw
        if( nibble0 & 1 )
        {
          cmd.itype  = I196_djnzw;
          cmd.Op1.dtyp = dt_word;
        }
        else
          cmd.itype  = I196_djnz;

        cmd.Op1.type = o_mem;
        cmd.Op1.addr = map(ua_next_byte());
        offc = ua_next_byte();
        cmd.Op2.type = o_near;
        cmd.Op2.addr = truncate(cmd.ip + cmd.size + offc);  // signed addition
        break;

      case 0x2:                 // tijmp
        cmd.itype     = I196_tijmp;
        cmd.Op1.dtyp  = cmd.Op2.dtyp = dt_word;
        cmd.Op2.type  = o_indirect;
        cmd.Op2.addr  = map(ua_next_byte());
        cmd.Op3.type  = o_imm;
        cmd.Op3.value = ua_next_byte();
        cmd.Op1.type  = o_mem;
        cmd.Op1.addr  = map(ua_next_byte());
        break;

      case 0x3:                 // br
        cmd.itype     = extended ? I196_ebr : I196_br;
        aop(2, cmd.Op1);
        break;

      case 0x4:                 // ebmovi
        if ( !extended ) return 0;
        cmd.itype = I196_ebmovi;
        cmd.Op1.type = o_mem;
        cmd.Op1.addr = map(ua_next_byte());
        cmd.Op2.type = o_mem;
        cmd.Op2.addr = map(ua_next_byte());
        break;

      case 0x6:                 // ejmp
        if ( !extended ) return 0;
        cmd.itype    = I196_ejmp;
        cmd.Op1.type = o_near;
        off = ua_next_word();
        off |= int32(ua_next_byte()) << 16;
        cmd.Op1.addr = truncate(cmd.ip + cmd.size + off);   // signed addition
        break;

      case 0x8:                 // eld.indirect
      case 0x9:                 // eld.indexed
        return ld_st(I196_eld, dt_word, nibble0 == 0x8, cmd.Op1, cmd.Op2);

      case 0xA:                 // eldb.indirect
      case 0xB:                 // eldb.indexed
        return ld_st(I196_eldb, dt_byte, nibble0 == 0xA, cmd.Op1, cmd.Op2);

      case 0xC:                 // dpts
        cmd.itype = I196_dpts;
        break;

      case 0xD:                 // epts
        cmd.itype = I196_epts;
        break;

      case 0x7: case 0xF:       // ljmp, lcall
        cmd.itype    = (nibble0 & 8) ? I196_lcall : I196_ljmp;
        cmd.Op1.type = o_near;
        off = short(ua_next_word());
        cmd.Op1.addr = truncate(cmd.ip + cmd.size + off);   // signed addition
        cmd.Op1.dtyp = dt_word;
        break;

      default:
        return 0;
    }
  }
  else
  {
    static const char cmdf[] =
    {
      I196_ret,   I196_ecall,I196_pushf, I196_popf,
      I196_pusha, I196_popa, I196_idlpd, I196_trap,
      I196_clrc,  I196_setc, I196_di,    I196_ei,
      I196_clrvt, I196_nop,  I196_null,  I196_rst
    };

    cmd.itype = cmdf[nibble0];
    if ( nibble0 == 1 ) // ecall
    {
      if( !extended ) return 0;
      off = ua_next_word();
      off |= int32(ua_next_byte()) << 16;
      cmd.Op1.type = o_near;
      cmd.Op1.addr = truncate(cmd.ip + cmd.size + off);
    }
    else if( nibble0 == 6 )        // idlpd
    {
      cmd.Op1.type  = o_imm;
      cmd.Op1.value = ua_next_byte();
    }
    else if( nibble0 == 0xE ) // prefix
    {
      code = ua_next_byte();

      switch( code & 0xFC )
      {
        case 0x4C: case 0x5C:
          if( code & 0x10 )
          {
            cmd.itype = I196_mulb3;
            cmd.Op1.dtyp = dt_word;
          }
          else
          {
            cmd.itype = I196_mul3;
            cmd.Op3.dtyp = cmd.Op2.dtyp = dt_word;
            cmd.Op1.dtyp = dt_dword;
          }

          aop( code, cmd.Op3 );
          cmd.Op2.addr = map(ua_next_byte());
          cmd.Op2.type = o_mem;
          cmd.Op1.addr = map(ua_next_byte());
          cmd.Op1.type = o_mem;
          break;

        case 0x6C: case 0x7C: case 0x8C: case 0x9C:
          cmd.itype = (code & 0x80) ?
            (code & 0x10) ? I196_divb  : I196_div :
            (code & 0x10) ? I196_mulb2 : I196_mul2;

          if( code & 0x10 )
            cmd.Op1.dtyp = dt_word;
          else
          {
            cmd.Op1.dtyp = dt_dword;
            cmd.Op2.dtyp = dt_word;
          }

          aop( code, cmd.Op2 );
          cmd.Op1.addr = map(ua_next_byte());
          cmd.Op1.type = o_mem;
          break;

        default:
          return 0;
      }
    }
  }

  return cmd.size;
}
