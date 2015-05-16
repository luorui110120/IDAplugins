/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *      Microchip's PIC
 *
 */

#include "pic.hpp"
#include <srarea.hpp>

static int basic_ana(void);

#define PIC18_IP_RANGE 0x1FFFFF

//--------------------------------------------------------------------------
static int ana(ea_t ea, insn_t &insn)
{
  insn_t saved = cmd;
  int len = decode_insn(ea);
  if ( len ) insn = cmd;
  cmd = saved;
  return len;
}

//--------------------------------------------------------------------------
// may use the second instruction for the macro:
//  - no crefs to the second instruction of the macro
//  - nothing there

static bool may_grow(void)
{
  flags_t F = get_flags_novalue(cmd.ea+1);
  return (isUnknown(F) || isTail(F)) && !hasRef(F);
}

int idaapi ana(void)
{
  static bool inside = false;
  int len = basic_ana();
  if ( inside || len == 0 ) return len;
  if ( macro() )
  {
    inside = true;
    switch ( cmd.itype )
    {
// movfw   macro   f       ; Move Contents of File Reg to W
//      movf    f,0
//      endm
// tstf    macro   f       ; Test Contents of File Register
//      movf    f,1
//      endm
      case PIC_movf:
        cmd.itype = (cmd.Op2.reg == W) ? PIC_movfw : PIC_tstf;
        cmd.Op2.type = o_void;
        break;

// negf    macro   f,d     ; Negate File Register Contents
//      comf    f,1
//      incf    f,d
//      endm
      case PIC_comf:
        if ( cmd.Op2.reg == F && may_grow() )
        {
          insn_t incf;
          if ( ana(cmd.ea+1, incf)
            && incf.itype == PIC_incf
            && incf.Op1.type == o_mem
            && incf.Op1.addr == cmd.Op1.addr )
          {
            cmd.itype = PIC_negf;
            cmd.Op2.reg = incf.Op2.reg;
            cmd.size  = 2;
          }
        }
        break;

// b       macro   k       ; Branch to Address
//      goto    k
//      endm
      case PIC_goto:
        cmd.itype = PIC_b;
        break;

// clrc    macro           ; Clear Carry
//      bcf     3,0
//      endm
// clrdc   macro           ; Clear Digit Carry
//      bcf     3,1
//      endm
// clrz    macro           ; Clear Zero
//      bcf     3,2
//      endm
      case PIC_bcf:
        if ( is_bank() ) switch ( cmd.Op2.value )
        {
          case 0: cmd.itype = PIC_clrc;  goto NOOP;
          case 1: cmd.itype = PIC_clrdc; goto NOOP;
          case 2: cmd.itype = PIC_clrz;  goto NOOP;
NOOP:
            cmd.Op1.type = o_void;
            cmd.Op2.type = o_void;
            break;
        }
        break;

// setc    macro           ; Set Carry
//      bsf     3,0
//      endm
// setdc   macro           ; Set Digit Carry
//      bsf     3,1
//      endm
// setz    macro           ; Set Zero
//      bcf     3,2
//      endm
      case PIC_bsf:
        if ( is_bank() ) switch ( cmd.Op2.value )
        {
          case 0: cmd.itype = PIC_setc;  goto NOOP;
          case 1: cmd.itype = PIC_setdc; goto NOOP;
          case 2: cmd.itype = PIC_setz;  goto NOOP;
        }
        break;

// skpnc   macro           ; Skip on No Carry
//      btfsc   3,0
//      endm
// skpndc  macro           ; Skip on No Digit Carry
//      btfsc   3,1
//      endm
// skpnz   macro           ; Skip on No Zero
//      btfsc   3,2
//      endm
      case PIC_btfsc:
        if ( is_bank() ) switch ( cmd.Op2.value )
        {
          case 0: cmd.itype = PIC_skpnc;  goto NOOP_BTF;
          case 1: cmd.itype = PIC_skpndc; goto NOOP_BTF;
          case 2: cmd.itype = PIC_skpnz;  goto NOOP_BTF;
        }
        break;

// skpc    macro           ; Skip on Carry
//      BTFSS   3,0
//      endm
// skpdc   macro           ; Skip on Digit Carry
//      btfss   3,1
//      endm
// skpz    macro           ; Skip on Zero
//      btfss   3,2
//      endm
      case PIC_btfss:
        if ( is_bank() ) switch ( cmd.Op2.value )
        {
          case 0: cmd.itype = PIC_skpc;  goto NOOP_BTF;
          case 1: cmd.itype = PIC_skpdc; goto NOOP_BTF;
          case 2: cmd.itype = PIC_skpz;  goto NOOP_BTF;
        }
        break;
NOOP_BTF:
        cmd.Op1.type = o_void;
        cmd.Op2.type = o_void;
        if ( may_grow() )
        {
          insn_t b;
          if ( ana(cmd.ea+1, b) ) switch ( b.itype )
          {
// bnc     macro   k       ; Branch on No Carry to k
//      btfss   3,0
//      goto    k
//      endm
// bndc    macro   k       ; Branch on No Digit Carry to k
//      btfss   3,1
//      goto    k
//      endm
// bnz     macro   k       ; Branch on No Zero to Address
//      btfss   3,2
//      goto    k
//      endm
// bc      macro   k       ; Branch on Carry to Address k
//      btfsc   3,0
//      goto    k
//      endm
// bdc     macro   k       ; Branch on Digit Carry to k
//      btfsc   3,1
//      goto    k
//      endm
// bz      macro   k       ; Branch on Zero to Address k
//      btfsc   3,2
//      goto    k
//      endm
            case PIC_goto:
              cmd.Op1  = b.Op1;
              cmd.size = 2;
              cmd.itype = (cmd.itype == PIC_skpc)  ? PIC_bnc :
                          (cmd.itype == PIC_skpdc) ? PIC_bndc:
                          (cmd.itype == PIC_skpz)  ? PIC_bnz :
                          (cmd.itype == PIC_skpnc) ? PIC_bc  :
                          (cmd.itype == PIC_skpndc)? PIC_bdc : PIC_bz;
              break;
// addcf   macro   f,d     ; Add Carry to File Register
//      btfsc   3,0
//      incf    f,d
//      endm
// adddcf  macro   f,d     ; Add Digit to File Register
//      BTFSC   3,1
//      incf    f,d
//      endm
            case PIC_incf:
              if ( cmd.itype == PIC_skpnc )
              {
                cmd.itype = PIC_addcf;
                goto COPYOPS;
              }
              if ( cmd.itype == PIC_skpndc )
              {
                cmd.itype = PIC_adddcf;
COPYOPS:
                cmd.Op1 = b.Op1;
                cmd.Op2 = b.Op2;
                cmd.size = 2;
              }
              break;
// subcf   macro   f,d     ; Subtract Carry from File Reg
//      btfsc   3,0
//      decf    f,d
//      endm
            case PIC_decf:
              if ( cmd.itype == PIC_skpnc )
              {
                cmd.itype = PIC_subcf;
                goto COPYOPS;
              }
              break;
          }
        }
        break;
    }
    inside = false;
  }

  // if the instruction is too long, recreate it:
  if ( cmd.size == 1 && isTail(get_flags_novalue(cmd.ea+1)) )
  {
    auto_make_code(cmd.ea);
    auto_make_code(cmd.ea+1);
    ea_t saved = cmd.ea;
    do_unknown(cmd.ea, DOUNK_SIMPLE);    // destroys cmd.ea
    cmd.ea = saved;
  }
  return cmd.size;
}

//--------------------------------------------------------------------------
static void opf12(int code)
{
  cmd.Op1.type = o_mem;
  cmd.Op1.dtyp = dt_byte;
  sel_t v = getSR(cmd.ea, BANK);
  if ( v == BADSEL ) v = 0;
  cmd.Op1.addr = (code & 0x1F) | ((v&1) << 5);
}

//--------------------------------------------------------------------------
static void opf14(int code)
{
  cmd.Op1.type = o_mem;
  cmd.Op1.dtyp = dt_byte;
  sel_t v = getSR(cmd.ea, BANK);
  if ( v == BADSEL ) v = 0;
  cmd.Op1.addr = (code & 0x7F) | ((v&3) << 7);
}

//--------------------------------------------------------------------------
static void opfa16(int code)
{
  cmd.Op1.type = o_mem;
  cmd.Op1.dtyp = dt_byte;
  if ( code & 0x0100 ) // if a == 1 (BSR)
  {
    sel_t v = getSR(cmd.ea, BANK);
    if ( v == BADSEL ) v = 0;
    cmd.Op1.addr = ((v&0xF) << 8) | (code & 0xFF);
  }
  else                 // if a == 0 (access bank)
  {
    cmd.Op1.addr = code & 0xFF;
    if ( cmd.Op1.addr >= 128 ) cmd.Op1.addr = 3840 + cmd.Op1.addr;
  }
}

//--------------------------------------------------------------------------
static void basic_ana12(int code)
{
  int b4;

  switch ( code >> 10 )
  {
    case 0:
// 0000 0100 0000 CLRW                   Clear W
// 0000 0000 0000 NOP                    No Operation
// 0000 0000 0100 CLRWDT                 Clear Watchdog Timer
// 0000 0000 0010 OPTION                 Load OPTION register
// 0000 0000 0011 SLEEP                  Go into standby mode
           if ( code == 0x040 ) cmd.itype = PIC_clrw;
      else if ( code == 0x000 ) cmd.itype = PIC_nop;
      else if ( code == 0x004 ) cmd.itype = PIC_clrwdt;
      else if ( code == 0x002 ) cmd.itype = PIC_option;
      else if ( code == 0x003 ) cmd.itype = PIC_sleep;
      else if ( ( code & 0xFF8 ) == 0 )
      {
// 0000 0000 0fff TRIS    f (4<f<8)      Load TRIS Register
        cmd.itype = PIC_tris;
        opf12(code);
      }
      else if ( ( code & 0xF80 ) == 0 )
// 0000 001f ffff MOVWF   f              Move W to f
// 0000 011f ffff CLRF    f              Clear f
      {
        static ushort codes[4] =
        {
          PIC_null, PIC_movwf, PIC_null, PIC_clrf
        };
        cmd.itype = codes[(code>>5)&3];
        opf12(code);
      }
      else
      {
// 0000 10df ffff SUBWF   f, d           Subtract W from f
// 0000 11df ffff DECF    f, d           Decrement f
// 0001 00df ffff IORWF   f, d           Inclusive OR W with f
// 0001 01df ffff ANDWF   f, d           AND W with f
// 0001 10df ffff XORWF   f, d           Exclusive OR W with f
// 0001 11df ffff ADDWF   f, d           Add W and f
// 0010 00df ffff MOVF    f, d           Move f
// 0010 01df ffff COMF    f, d           Complement f
// 0010 10df ffff INCF    f, d           Increment f
// 0010 11df ffff DECFSZ  f, d           Decrement f, Skip if 0
// 0011 00df ffff RRF     f, d           Rotate Right f through Carry
// 0011 01df ffff RLF     f, d           Rotate Left f through Carry
// 0011 10df ffff SWAPF   f, d           Swap nibbles in f
// 0011 11df ffff INCFSZ  f, d           Increment f, Skip if 0
        b4 = code >> 6;
        static ushort codes[16] =
        {
          PIC_null,  PIC_null,  PIC_subwf, PIC_decf,
          PIC_iorwf, PIC_andwf, PIC_xorwf, PIC_addwf,
          PIC_movf,  PIC_comf,  PIC_incf,  PIC_decfsz,
          PIC_rrf,   PIC_rlf,   PIC_swapf, PIC_incfsz
        };
        cmd.itype = codes[b4];
        opf12(code);
        cmd.Op2.type = o_reg;
        cmd.Op2.reg  = (code & 0x20) ? F : W;
        cmd.Op2.dtyp = dt_byte;
      }
      break;
    case 1:
// 0100 bbbf ffff BCF     f, b           Bit Clear f
// 0101 bbbf ffff BSF     f, b           Bit Set f
// 0110 bbbf ffff BTFSC   f, b           Bit Test f, Skip if Clear
// 0111 bbbf ffff BTFSS   f, b           Bit Test f, Skip if Set
      {
        static ushort codes[4] =
        {
          PIC_bcf, PIC_bsf, PIC_btfsc, PIC_btfss
        };
        cmd.itype = codes[(code>>8)&3];
        opf12(code);
        cmd.Op2.type  = o_imm;
        cmd.Op2.value = (code >> 5) & 7;
        cmd.Op2.dtyp  = dt_byte;
      }
      break;
    case 2:
      b4 = (code >> 8) & 0x3;
      switch ( b4 )
      {
        case 0:
// 1000 kkkk kkkk RETLW   k              Return with literal in W
          cmd.itype = PIC_retlw;
          cmd.Op1.type  = o_imm;
          cmd.Op1.value = code & 0xFF;
          cmd.Op1.dtyp  = dt_byte;
          break;
        case 1:
// 1001 kkkk kkkk CALL    k              Call subroutine
          {
            // old databases used status reg (PCLATH) for hight bit of the address
            // new code uses BANK for that
            // so we get both and try to guess
            sel_t status = getSR(cmd.ea, PCLATH);
            sel_t bank = getSR(cmd.ea, BANK);
            if ( (status != BADSEL && status != 0) && (bank == BADSEL || bank==0) )
              bank = (status >> 5) & 3;
            cmd.itype = PIC_call;
            cmd.Op1.type = o_near;
            cmd.Op1.addr = ( bank << 9 ) | ( code & 0xFF );
            cmd.Op1.dtyp = dt_code;
          }
          break;
        default:
// 101k kkkk kkkk GOTO    k              Go to address
          {
            sel_t status = getSR(cmd.ea, PCLATH);
            sel_t bank = getSR(cmd.ea, BANK);
            if ( (status != BADSEL && status != 0) && (bank == BADSEL || bank==0) )
              bank = (status >> 5) & 3;
            cmd.itype = PIC_goto;
            cmd.Op1.type = o_near;
            cmd.Op1.addr = ( bank << 9 ) | ( code & 0x1FF );
            cmd.Op1.dtyp = dt_code;
          }
          break;
      }
      break;
    case 3:
// 1100 kkkk kkkk MOVLW   k              Move literal to W
// 1101 kkkk kkkk IORLW   k              Inclusive OR literal with W
// 1110 kkkk kkkk ANDLW   k              AND literal with W
// 1111 kkkk kkkk XORLW   k              Exclusive OR literal with W
      {
        static ushort codes[4] =
        {
          PIC_movlw, PIC_iorlw, PIC_andlw, PIC_xorlw
        };
        cmd.itype = codes[(code>>8)&3];
        cmd.Op1.type  = o_imm;
        cmd.Op1.value = (uchar)code;
        cmd.Op1.dtyp  = dt_byte;
      }
      break;
  }
}

//--------------------------------------------------------------------------
static void basic_ana14(int code)
{
  int b4 = (code >> 8) & 0xF;

  switch ( code >> 12 )
  {
    case 0:
      if ( b4 == 0 )
      {
// 00 0000 1fff ffff MOVWF   f           Move W to f
        if ( code & 0x80 )
        {
          cmd.itype = PIC_movwf;
          opf14(code);
          break;
        }
// 00 0000 0xx0 0000 NOP                 No Operation
        if ( (code & 0x3F9F) == 0 )
        {
          cmd.itype = PIC_nop;
          break;
        }
// 00 0000 0000 1000 RETURN              Return from Subroutine
// 00 0000 0000 1001 RETFIE              Return from interrupt
// 00 0000 0110 0010 OPTION              Load OPTION register
// 00 0000 0110 0011 SLEEP               Go into standby mode
// 00 0000 0110 0100 CLRWDT              Clear Watchdog Timer
// 00 0000 0110 0fff TRIS   f (4<f<8)    Load TRIS Register
             if ( code == 0x0008 ) cmd.itype = PIC_return;
        else if ( code == 0x0009 ) cmd.itype = PIC_retfie;
        else if ( code == 0x0062 ) cmd.itype = PIC_option;
        else if ( code == 0x0063 ) cmd.itype = PIC_sleep;
        else if ( code == 0x0064 ) cmd.itype = PIC_clrwdt;
        else if ( code >= 0x0065 && code <= 0x0067 )
        {
          cmd.itype = PIC_tris;
          cmd.Op1.type = o_imm;
          cmd.Op1.dtyp = dt_byte;
          cmd.Op1.value = code & 7;
        }
      }
      else if ( b4 == 1 )
      {
// 00 0001 1fff ffff CLRF    f           Clear f
        if ( code & 0x80 )
        {
          cmd.itype = PIC_clrf;
          opf14(code);
        }
// 00 0001 0xxx xxxx CLRW                Clear W
        else
        {
          cmd.itype = PIC_clrw;
        }
      }
      else
      {
// 00 0010 dfff ffff SUBWF   f, d        Subtract W from f
// 00 0011 dfff ffff DECF    f, d        Decrement f
// 00 0100 dfff ffff IORWF   f, d        Inclusive OR W with f
// 00 0101 dfff ffff ANDWF   f, d        AND W with f
// 00 0110 dfff ffff XORWF   f, d        Exclusive OR W with f
// 00 0111 dfff ffff ADDWF   f, d        Add W and f
// 00 1000 dfff ffff MOVF    f, d        Move f
// 00 1001 dfff ffff COMF    f, d        Complement f
// 00 1010 dfff ffff INCF    f, d        Increment f
// 00 1011 dfff ffff DECFSZ  f, d        Decrement f, Skip if 0
// 00 1100 dfff ffff RRF     f, d        Rotate Right f through Carry
// 00 1101 dfff ffff RLF     f, d        Rotate Left f through Carry
// 00 1110 dfff ffff SWAPF   f, d        Swap nibbles in f
// 00 1111 dfff ffff INCFSZ  f, d        Increment f, Skip if 0
        static ushort codes[16] =
        {
          PIC_null,  PIC_null,  PIC_subwf, PIC_decf,
          PIC_iorwf, PIC_andwf, PIC_xorwf, PIC_addwf,
          PIC_movf,  PIC_comf,  PIC_incf,  PIC_decfsz,
          PIC_rrf,   PIC_rlf,   PIC_swapf, PIC_incfsz
        };
        cmd.itype = codes[b4];
        opf14(code);
        cmd.Op2.type = o_reg;
        cmd.Op2.reg  = (code & 0x80) ? F : W;
        cmd.Op2.dtyp = dt_byte;
      }
      break;
    case 1:
// 01 00bb bfff ffff BCF     f, b        Bit Clear f
// 01 01bb bfff ffff BSF     f, b        Bit Set f
// 01 10bb bfff ffff BTFSC   f, b        Bit Test f, Skip if Clear
// 01 11bb bfff ffff BTFSS   f, b        Bit Test f, Skip if Set
      {
        static ushort codes[4] =
        {
          PIC_bcf, PIC_bsf, PIC_btfsc, PIC_btfss
        };
        cmd.itype = codes[(code>>10)&3];
        opf14(code);
        cmd.Op2.type  = o_imm;
        cmd.Op2.value = (code >> 7) & 7;
        cmd.Op2.dtyp  = dt_byte;
      }
      break;
    case 2:
// 10 0kkk kkkk kkkk CALL    k           Call subroutine
// 10 1kkk kkkk kkkk GOTO    k           Go to address
      {
        sel_t pclath = getSR(cmd.ea, PCLATH) & 0x18; // & 00011000b
        cmd.itype = (code & 0x800) ? PIC_goto : PIC_call;
        cmd.Op1.type = o_near;
        cmd.Op1.addr = (pclath << (11-3)) | (code & 0x7FF);
        cmd.Op1.dtyp = dt_code;
      }
      break;
    case 3:
// 11 00xx kkkk kkkk MOVLW   k           Move literal to W
// 11 01xx kkkk kkkk RETLW   k           Return with literal in W
// 11 1000 kkkk kkkk IORLW   k           Inclusive OR literal with W
// 11 1001 kkkk kkkk ANDLW   k           AND literal with W
// 11 1010 kkkk kkkk XORLW   k           Exclusive OR literal with W
// 11 110x kkkk kkkk SUBLW   k           Subtract W from literal
// 11 111x kkkk kkkk ADDLW   k           Add literal and W
      {
        static ushort codes[16] =
        {
          PIC_movlw, PIC_movlw, PIC_movlw, PIC_movlw,
          PIC_retlw, PIC_retlw, PIC_retlw, PIC_retlw,
          PIC_iorlw, PIC_andlw, PIC_xorlw, PIC_null,
          PIC_sublw, PIC_sublw, PIC_addlw, PIC_addlw
        };
        cmd.itype = codes[b4];
        cmd.Op1.type  = o_imm;
        cmd.Op1.value = code & 0xFF;
        cmd.Op1.dtyp  = dt_byte;
      }
      break;
  }
}

//--------------------------------------------------------------------------
int get_signed(int byte,int mask)
{
  int bits = mask >> 1;
  int sign = bits + 1;
  if ( byte & sign ) // offset < 0
  {
    byte = ( byte & bits ) - sign;
  }
  else // offset >= 0
  {
    byte = byte & mask;
  }
  return byte;
}

//--------------------------------------------------------------------------
static void basic_ana16(int code)
{
  if ( ( code >> 12 ) == 0 )
  {
    int b3 =  code >> 4;
    if ( b3 == 0 )
    {
// 0000 0000 0000 0000 NOP               No Operation
// 0000 0000 0000 0011 SLEEP             Go into standby mode
// 0000 0000 0000 0100 CLRWDT            Clear Watchdog Timer
// 0000 0000 0000 0101 PUSH              Push top of return stack
// 0000 0000 0000 0110 POP               Pop top of return stack
// 0000 0000 0000 0111 DAW               Decimal Adjust W
// 0000 0000 0000 1000 TBLRD*            Table Read
// 0000 0000 0000 1001 TBLRD*+           Table Read with post-increment
// 0000 0000 0000 1010 TBLRD*-           Table Read with post-decrement
// 0000 0000 0000 1011 TBLRD+*           Table Read with pre-increment
// 0000 0000 0000 1100 TBLWT*            Table Write
// 0000 0000 0000 1101 TBLWT*+           Table Write with post-increment
// 0000 0000 0000 1110 TBLWT*-           Table Write with post-decrement
// 0000 0000 0000 1111 TBLWT+*           Table Write with pre-increment
      static ushort codes[16] =
      {
        PIC_nop,    PIC_null,    PIC_null,    PIC_sleep,
        PIC_clrwdt, PIC_push0,   PIC_pop0,    PIC_daw0,
        PIC_tblrd0, PIC_tblrd0p, PIC_tblrd0m, PIC_tblrdp0,
        PIC_tblwt0, PIC_tblwt0p, PIC_tblwt0m, PIC_tblwtp0
      };
      cmd.itype = codes[code];
    }
    else if ( b3 < 0x80 )
    {
      if ( ( code & 0xFFFC ) == 0x0010 )
      {
// 0000 0000 0001 000s RETFIE s          Return from interrupt enable
// 0000 0000 0001 001s RETURN s          Return from Subroutine
        cmd.itype = (code & 0x2) ? PIC_return1 : PIC_retfie1;
        if ( code & 1 )
        {
          cmd.Op1.type  = o_reg;
          cmd.Op1.reg   = FAST;
        }
        else
        {
          cmd.Op1.type  = o_imm;
          cmd.Op1.value = 0;
        }
        cmd.Op1.dtyp  = dt_byte;
      }
      else if ( code == 0x00FF )
      {
// 0000 0000 1111 1111 RESET             Software device Reset
        cmd.itype = PIC_reset0;
      }
      else if ( ( code & 0xFFF0 ) == 0x0100 )
      {
// 0000 0001 0000 kkkk MOVLB  k          Move literal to BSR
        cmd.itype = PIC_movlb1;
        cmd.Op1.type  = o_imm;
        cmd.Op1.value = code & 0xF;
        cmd.Op1.dtyp  = dt_byte;
      }
      else if ( ( code & 0xFE00 ) == 0x0200 )
      {
// 0000 001a ffff ffff MULWF  f, a       Multiply W with f
        cmd.itype = PIC_mulwf2;
        opfa16(code);
        cmd.Op2.type = o_reg;
        cmd.Op2.reg  = (code & 0x100) ? BANKED : ACCESS;
        cmd.Op2.dtyp = dt_byte;
      }
      else if ( ( code & 0xFC00 ) == 0x0400 )
      {
// 0000 01da ffff ffff DECF   f, d, a    Decrement f
        cmd.itype = PIC_decf3;
        opfa16(code);
        cmd.Op2.type = o_reg;
        cmd.Op2.reg  = (code & 0x200) ? F : W;
        cmd.Op2.dtyp = dt_byte;
        cmd.Op3.type = o_reg;
        cmd.Op3.reg  = (code & 0x100) ? BANKED : ACCESS;
        cmd.Op3.dtyp = dt_byte;
      }
      else cmd.itype = PIC_null;
    }
    else
    {
// 0000 1000 kkkk kkkk SUBLW  k          Subtract W from literal
// 0000 1001 kkkk kkkk IORLW  k          Inclusive OR literal with W
// 0000 1010 kkkk kkkk XORLW  k          Exclusive OR literal with W
// 0000 1011 kkkk kkkk ANDLW  k          AND literal with W
// 0000 1100 kkkk kkkk RETLW  k          Return with literal in W
// 0000 1101 kkkk kkkk MULLW  k          Multiply literal with W
// 0000 1110 kkkk kkkk MOVLW  k          Move literal to W
// 0000 1111 kkkk kkkk ADDLW  k          Add literal and W
      static ushort codes[16] =
      {
        PIC_sublw, PIC_iorlw,  PIC_xorlw, PIC_andlw,
        PIC_retlw, PIC_mullw1, PIC_movlw, PIC_addlw
      };
      cmd.itype = codes[(code>>8)&7];
      cmd.Op1.type  = o_imm;
      cmd.Op1.value = (char)code;
      cmd.Op1.dtyp  = dt_byte;
    }
  }
  else if ( ( code >> 14 ) <= 2 )
  {
    int b1 =  code >> 12;
    if ( b1 <= 5 )
    {
// 0001 00da ffff ffff IORWF  f, d, a    Inclusive OR W with f
// 0001 01da ffff ffff ANDWF  f, d, a    AND W with f
// 0001 10da ffff ffff XORWF  f, d, a    Exclusive OR W with f
// 0001 11da ffff ffff COMF   f, d, a    Complement f
// 0010 00da ffff ffff ADDWFC f, d, a    Add W and Carry to f
// 0010 01da ffff ffff ADDWF  f, d, a    Add W and f
// 0010 10da ffff ffff INCF   f, d, a    Increment f
// 0010 11da ffff ffff DECFSZ f, d, a    Decrement f, Skip if 0
// 0011 00da ffff ffff RRCF   f, d, a    Rotate Right f through Carry
// 0011 01da ffff ffff RLCF   f, d, a    Rotate Left f through Carry
// 0011 10da ffff ffff SWAPF  f, d, a    Swap nibbles in f
// 0011 11da ffff ffff INCFSZ f, d, a    Increment f, Skip if 0
// 0100 00da ffff ffff RRNCF  f, d, a    Rotate Right f
// 0100 01da ffff ffff RLNCF  f, d, a    Rotate Left f
// 0100 10da ffff ffff INFSNZ f, d, a    Increment f, Skip if not 0
// 0100 11da ffff ffff DCFSNZ f, d, a    Decrement f, Skip if not 0
// 0101 00da ffff ffff MOVF   f, d, a    Move f
// 0101 01da ffff ffff SUBFWB f, d, a    Substract f from W with borrow
// 0101 10da ffff ffff SUBWFB f, d, a    Substract W from f with borrow
// 0101 11da ffff ffff SUBWF  f, d, a    Substract W from f
      static ushort codes[24] =
      {
        PIC_null,    PIC_null,    PIC_null,    PIC_null,
        PIC_iorwf3,  PIC_andwf3,  PIC_xorwf3,  PIC_comf3,
        PIC_addwfc3, PIC_addwf3,  PIC_incf3,   PIC_decfsz3,
        PIC_rrcf3,   PIC_rlcf3,   PIC_swapf3,  PIC_incfsz,
        PIC_rrncf3,  PIC_rlncf3,  PIC_infsnz3, PIC_dcfsnz3,
        PIC_movf3,   PIC_subfwb3, PIC_subwfb3, PIC_subwf3,
      };
      cmd.itype = codes[code>>10];
      opfa16(code);
      cmd.Op2.type = o_reg;
      cmd.Op2.reg  = (code & 0x200) ? F : W;
      cmd.Op2.dtyp = dt_byte;
      cmd.Op3.type = o_reg;
      cmd.Op3.reg  = (code & 0x100) ? BANKED : ACCESS;
      cmd.Op3.dtyp = dt_byte;
    }
    else if ( b1 == 6 )
    {
// 0110 000a ffff ffff CPFSLT f, a       Compare f with W, Skip if <
// 0110 001a ffff ffff CPFSEQ f, a       Compare f with W, Skip if ==
// 0110 010a ffff ffff CPFSGT f, a       Compare f with W, Skip if >
// 0110 011a ffff ffff TSTFSZ f, a       Test f, Skip if 0
// 0110 100a ffff ffff SETF   f, a       Set f
// 0110 101a ffff ffff CLRF   f, a       Clear f
// 0110 110a ffff ffff NEGF   f, a       Negate f
// 0110 111a ffff ffff MOVWF  f, a       Move W to f
      static ushort codes[8] =
      {
        PIC_cpfslt2, PIC_cpfseq2, PIC_cpfsgt2, PIC_tstfsz2,
        PIC_setf2,   PIC_clrf2,   PIC_negf2,   PIC_movwf2,
      };
      cmd.itype = codes[(code>>9)&0xF];
      opfa16(code);
      cmd.Op2.type = o_reg;
      cmd.Op2.reg  = (code & 0x100) ? BANKED : ACCESS;
      cmd.Op2.dtyp = dt_byte;
    }
    else
    {
// 0111 bbba ffff ffff BTG    f, b, a    Bit Toggle f
// 1000 bbba ffff ffff BSF    f, b, a    Bit Set f
// 1001 bbba ffff ffff BCF    f, b, a    Bit Clear f
// 1010 bbba ffff ffff BTFSS  f, b, a    Bit Test f, Skip if Set
// 1011 bbba ffff ffff BTFSC  f, b, a    Bit Test f, Skip if Clear
      static ushort codes[5] =
      {
        PIC_btg3, PIC_bsf3, PIC_bcf3, PIC_btfss3, PIC_btfsc3
      };
      cmd.itype = codes[(code>>12)-7];
      opfa16(code);
      cmd.Op2.type  = o_imm;
      cmd.Op2.value = (code >> 9) & 7;
      cmd.Op2.dtyp  = dt_byte;
      cmd.Op3.type = o_reg;
      cmd.Op3.reg  = (code & 0x100) ? BANKED : ACCESS;
      cmd.Op3.dtyp = dt_byte;
    }
  }
  else
  {
    int b2 = ( code >> 12 ) & 3;
    int b3 = ( code >> 8 ) & 0x0F;
    switch ( b2 )
    {
      case 0:
// 1100 ffff ffff ffff 1111 ffff ffff ffff MOVFF fs, fd  Move fs to fd
        cmd.itype = PIC_movff2;
        cmd.Op1.type = o_mem;
        cmd.Op1.dtyp = dt_byte;
        cmd.Op1.addr = code & 0xFFF;
        cmd.Op2.type = o_mem;
        cmd.Op2.dtyp = dt_byte;
        cmd.Op2.addr = ua_next_word() & 0xFFF;
        break;
      case 1:
// 1101 0nnn nnnn nnnn BRA    n          Branch unconditionally
// 1101 1nnn nnnn nnnn RCALL  n          Relative Call subroutine
        cmd.itype = (code & 0x800) ? PIC_rcall1 : PIC_bra1;
        cmd.Op1.type = o_near;
        cmd.Op1.addr = (cmd.ea + 2 + 2 * get_signed(code,0x07FF)) & PIC18_IP_RANGE;
        cmd.Op1.dtyp = dt_code;
        break;
      case 2:
        if ( b3 <= 7 )
        {
// 1110 0000 nnnn nnnn BZ     n          Branch if Zero
// 1110 0001 nnnn nnnn BNZ    n          Branch if not Zero
// 1110 0010 nnnn nnnn BC     n          Branch if Carry
// 1110 0011 nnnn nnnn BNC    n          Branch if not Carry
// 1110 0100 nnnn nnnn BOV    n          Branch if Overflow
// 1110 0101 nnnn nnnn BNOV   n          Branch if not Overflow
// 1110 0110 nnnn nnnn BN     n          Branch if Negative
// 1110 0111 nnnn nnnn BNN    n          Branch if not Negative
          static ushort codes[8] =
          {
            PIC_bz1,  PIC_bnz1,  PIC_bc1, PIC_bnc1,
            PIC_bov1, PIC_bnov1, PIC_bn1, PIC_bnn1
          };
          cmd.itype = codes[(code>>8)&7];
          cmd.Op1.type = o_near;
          cmd.Op1.addr = (cmd.ea + 2 + 2 * get_signed(code,0x00FF)) & PIC18_IP_RANGE;
          cmd.Op1.dtyp = dt_code;
        }
        else if ( b3 == 0xC || b3 == 0xD || b3 == 0xF )
        {
// 1110 110s kkkk kkkk 1111 kkkk kkkk kkkk CALL n, s     Call subroutine
// 1110 1111 kkkk kkkk 1111 kkkk kkkk kkkk GOTO n        Go to address
          static ushort codes[4] =
          {
            PIC_call2, PIC_call2, PIC_null, PIC_goto
          };
          cmd.itype = codes[(code>>8)&3];
          cmd.Op1.type = o_near;
          cmd.Op1.addr = ( (ua_next_word()& 0xFFF) << 9 ) | ( (code&0x00FF) << 1 );
          cmd.Op1.dtyp = dt_code;
          if ( cmd.itype == PIC_call2 )
          {
            if ( code & 0x0100 )
            {
              cmd.Op2.type  = o_reg;
              cmd.Op2.reg   = FAST;
            }
            else
            {
              cmd.Op2.type  = o_imm;
              cmd.Op2.value = 0;
            }
            cmd.Op2.dtyp = dt_byte;
          }
        }
        else if ( ( code & 0xFFC0 ) == 0xEE00 )
        {
// 1110 1110 00ff kkkk 1111 0000 kkkk kkkk LFSR f, k     Move literal to FSR
          cmd.itype = PIC_lfsr2;
          cmd.Op1.type  = o_reg;
          cmd.Op1.reg   = FSR0 + ( ( code >> 4 ) & 3 );
          cmd.Op1.dtyp = dt_byte;
          cmd.Op2.type  = o_imm;
          cmd.Op2.value = ( (code&0xF) << 8 ) | (ua_next_word() & 0xFF);
          cmd.Op2.dtyp  = dt_word;
        }
        else cmd.itype = PIC_null;
        break;
      case 3:
// 1111 xxxx xxxx xxxx NOP               No Operation
        cmd.itype = PIC_nop;
        break;
    }
  }
}

//--------------------------------------------------------------------------
static int basic_ana(void)
{
  int code;

  switch ( ptype )
  {
    case PIC12:
      code = get_full_byte(cmd.ea); cmd.size = 1;
      basic_ana12(code);
      break;
    case PIC14:
      code = get_full_byte(cmd.ea); cmd.size = 1;
      basic_ana14(code);
      break;
    case PIC16:
      code = ua_next_word();
      basic_ana16(code);
      break;
    default:
      error("interr: ana");
      break;
  }
  if ( cmd.itype == PIC_null ) return 0;
  return cmd.size;
}
