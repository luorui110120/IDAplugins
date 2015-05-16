/*
        PDB files: convert register number to text string.
        This file contains one function: print_pdb_register

*/

#ifdef __NT__
#include <pro.h>
#include "cvconst.h"

//----------------------------------------------------------------------
const char *print_pdb_register(int machine, int reg)
{
  // Register subset shared by all processor types,
  switch ( reg )
  {
    case CV_ALLREG_ERR:    return "[*err*]";
    case CV_ALLREG_TEB:    return "[*teb*]";
    case CV_ALLREG_TIMER:  return "[*timer*]";
    case CV_ALLREG_EFAD1:  return "[*efad1*]";
    case CV_ALLREG_EFAD2:  return "[*efad2*]";
    case CV_ALLREG_EFAD3:  return "[*efad3*]";
    case CV_ALLREG_VFRAME: return "[*vframe*]";
    case CV_ALLREG_HANDLE: return "[*handle*]";
    case CV_ALLREG_PARAMS: return "[*params*]";
    case CV_ALLREG_LOCALS: return "[*locals*]";
    case CV_ALLREG_TID:    return "[*tid*]";
    case CV_ALLREG_ENV:    return "[*env*]";
    case CV_ALLREG_CMDLN:  return "[*cmdln*]";
  }

  // Processor specific subsets
  switch ( machine )
  {
    case CV_CFL_8080:
    case CV_CFL_8086:
    case CV_CFL_80286:
    case CV_CFL_80386:
    case CV_CFL_80486:
    case CV_CFL_PENTIUM:
    case CV_CFL_PENTIUMII:
    case CV_CFL_PENTIUMIII:
      //  Register set for the Intel 80x86 and ix86 processor series
      //  (plus PCODE registers)
      switch ( reg )
      {
        case CV_REG_NONE:    return "none";
        case CV_REG_AL:      return "al";
        case CV_REG_CL:      return "cl";
        case CV_REG_DL:      return "dl";
        case CV_REG_BL:      return "bl";
        case CV_REG_AH:      return "ah";
        case CV_REG_CH:      return "ch";
        case CV_REG_DH:      return "dh";
        case CV_REG_BH:      return "bh";
        case CV_REG_AX:      return "ax";
        case CV_REG_CX:      return "cx";
        case CV_REG_DX:      return "dx";
        case CV_REG_BX:      return "bx";
        case CV_REG_SP:      return "sp";
        case CV_REG_BP:      return "bp";
        case CV_REG_SI:      return "si";
        case CV_REG_DI:      return "di";
        case CV_REG_EAX:     return "eax";
        case CV_REG_ECX:     return "ecx";
        case CV_REG_EDX:     return "edx";
        case CV_REG_EBX:     return "ebx";
        case CV_REG_ESP:     return "esp";
        case CV_REG_EBP:     return "ebp";
        case CV_REG_ESI:     return "esi";
        case CV_REG_EDI:     return "edi";
        case CV_REG_ES:      return "es";
        case CV_REG_CS:      return "cs";
        case CV_REG_SS:      return "ss";
        case CV_REG_DS:      return "ds";
        case CV_REG_FS:      return "fs";
        case CV_REG_GS:      return "gs";
        case CV_REG_IP:      return "ip";
        case CV_REG_FLAGS:   return "flags";
        case CV_REG_EIP:     return "eip";
        case CV_REG_EFLAGS:  return "eflags";
        case CV_REG_TEMP:    return "temp";          // PCODE Temp
        case CV_REG_TEMPH:   return "temph";         // PCODE TempH
        case CV_REG_QUOTE:   return "quote";         // PCODE Quote
        case CV_REG_PCDR3:   return "pcdr3";         // PCODE reserved
        case CV_REG_PCDR4:   return "pcdr4";         // PCODE reserved
        case CV_REG_PCDR5:   return "pcdr5";         // PCODE reserved
        case CV_REG_PCDR6:   return "pcdr6";         // PCODE reserved
        case CV_REG_PCDR7:   return "pcdr7";         // PCODE reserved
        case CV_REG_CR0:     return "cr0";           // CR0 -- control registers
        case CV_REG_CR1:     return "cr1";
        case CV_REG_CR2:     return "cr2";
        case CV_REG_CR3:     return "cr3";
        case CV_REG_CR4:     return "cr4";           // Pentium
        case CV_REG_DR0:     return "dr0";           // Debug register
        case CV_REG_DR1:     return "dr1";
        case CV_REG_DR2:     return "dr2";
        case CV_REG_DR3:     return "dr3";
        case CV_REG_DR4:     return "dr4";
        case CV_REG_DR5:     return "dr5";
        case CV_REG_DR6:     return "dr6";
        case CV_REG_DR7:     return "dr7";
        case CV_REG_GDTR:    return "gdtr";
        case CV_REG_GDTL:    return "gdtl";
        case CV_REG_IDTR:    return "idtr";
        case CV_REG_IDTL:    return "idtl";
        case CV_REG_LDTR:    return "ldtr";
        case CV_REG_TR:      return "tr";

        case CV_REG_PSEUDO1: return "pseudo1";
        case CV_REG_PSEUDO2: return "pseudo2";
        case CV_REG_PSEUDO3: return "pseudo3";
        case CV_REG_PSEUDO4: return "pseudo4";
        case CV_REG_PSEUDO5: return "pseudo5";
        case CV_REG_PSEUDO6: return "pseudo6";
        case CV_REG_PSEUDO7: return "pseudo7";
        case CV_REG_PSEUDO8: return "pseudo8";
        case CV_REG_PSEUDO9: return "pseudo9";

        case CV_REG_ST0:     return "st0";
        case CV_REG_ST1:     return "st1";
        case CV_REG_ST2:     return "st2";
        case CV_REG_ST3:     return "st3";
        case CV_REG_ST4:     return "st4";
        case CV_REG_ST5:     return "st5";
        case CV_REG_ST6:     return "st6";
        case CV_REG_ST7:     return "st7";
        case CV_REG_CTRL:    return "ctrl";
        case CV_REG_STAT:    return "stat";
        case CV_REG_TAG:     return "tag";
        case CV_REG_FPIP:    return "fpip";
        case CV_REG_FPCS:    return "fpcs";
        case CV_REG_FPDO:    return "fpdo";
        case CV_REG_FPDS:    return "fpds";
        case CV_REG_ISEM:    return "isem";
        case CV_REG_FPEIP:   return "fpeip";
        case CV_REG_FPEDO:   return "fpedo";

        case CV_REG_MM0:     return "mm0";
        case CV_REG_MM1:     return "mm1";
        case CV_REG_MM2:     return "mm2";
        case CV_REG_MM3:     return "mm3";
        case CV_REG_MM4:     return "mm4";
        case CV_REG_MM5:     return "mm5";
        case CV_REG_MM6:     return "mm6";
        case CV_REG_MM7:     return "mm7";

        case CV_REG_XMM0:    return "xmm0";  // KATMAI registers
        case CV_REG_XMM1:    return "xmm1";
        case CV_REG_XMM2:    return "xmm2";
        case CV_REG_XMM3:    return "xmm3";
        case CV_REG_XMM4:    return "xmm4";
        case CV_REG_XMM5:    return "xmm5";
        case CV_REG_XMM6:    return "xmm6";
        case CV_REG_XMM7:    return "xmm7";

        case CV_REG_XMM00:   return "xmm00"; // KATMAI sub-registers
        case CV_REG_XMM01:   return "xmm01";
        case CV_REG_XMM02:   return "xmm02";
        case CV_REG_XMM03:   return "xmm03";
        case CV_REG_XMM10:   return "xmm10";
        case CV_REG_XMM11:   return "xmm11";
        case CV_REG_XMM12:   return "xmm12";
        case CV_REG_XMM13:   return "xmm13";
        case CV_REG_XMM20:   return "xmm20";
        case CV_REG_XMM21:   return "xmm21";
        case CV_REG_XMM22:   return "xmm22";
        case CV_REG_XMM23:   return "xmm23";
        case CV_REG_XMM30:   return "xmm30";
        case CV_REG_XMM31:   return "xmm31";
        case CV_REG_XMM32:   return "xmm32";
        case CV_REG_XMM33:   return "xmm33";
        case CV_REG_XMM40:   return "xmm40";
        case CV_REG_XMM41:   return "xmm41";
        case CV_REG_XMM42:   return "xmm42";
        case CV_REG_XMM43:   return "xmm43";
        case CV_REG_XMM50:   return "xmm50";
        case CV_REG_XMM51:   return "xmm51";
        case CV_REG_XMM52:   return "xmm52";
        case CV_REG_XMM53:   return "xmm53";
        case CV_REG_XMM60:   return "xmm60";
        case CV_REG_XMM61:   return "xmm61";
        case CV_REG_XMM62:   return "xmm62";
        case CV_REG_XMM63:   return "xmm63";
        case CV_REG_XMM70:   return "xmm70";
        case CV_REG_XMM71:   return "xmm71";
        case CV_REG_XMM72:   return "xmm72";
        case CV_REG_XMM73:   return "xmm73";

        case CV_REG_XMM0L:   return "xmm0l";
        case CV_REG_XMM1L:   return "xmm1l";
        case CV_REG_XMM2L:   return "xmm2l";
        case CV_REG_XMM3L:   return "xmm3l";
        case CV_REG_XMM4L:   return "xmm4l";
        case CV_REG_XMM5L:   return "xmm5l";
        case CV_REG_XMM6L:   return "xmm6l";
        case CV_REG_XMM7L:   return "xmm7l";

        case CV_REG_XMM0H:   return "xmm0h";
        case CV_REG_XMM1H:   return "xmm1h";
        case CV_REG_XMM2H:   return "xmm2h";
        case CV_REG_XMM3H:   return "xmm3h";
        case CV_REG_XMM4H:   return "xmm4h";
        case CV_REG_XMM5H:   return "xmm5h";
        case CV_REG_XMM6H:   return "xmm6h";
        case CV_REG_XMM7H:   return "xmm7h";

        case CV_REG_MXCSR:   return "mxcsr"; // XMM status register

        case CV_REG_EDXEAX:  return "edxeax";// EDX";EAX pair

        case CV_REG_EMM0L:   return "emm0l"; // XMM sub-registers (WNI integer)
        case CV_REG_EMM1L:   return "emm1l";
        case CV_REG_EMM2L:   return "emm2l";
        case CV_REG_EMM3L:   return "emm3l";
        case CV_REG_EMM4L:   return "emm4l";
        case CV_REG_EMM5L:   return "emm5l";
        case CV_REG_EMM6L:   return "emm6l";
        case CV_REG_EMM7L:   return "emm7l";

        case CV_REG_EMM0H:   return "emm0h";
        case CV_REG_EMM1H:   return "emm1h";
        case CV_REG_EMM2H:   return "emm2h";
        case CV_REG_EMM3H:   return "emm3h";
        case CV_REG_EMM4H:   return "emm4h";
        case CV_REG_EMM5H:   return "emm5h";
        case CV_REG_EMM6H:   return "emm6h";
        case CV_REG_EMM7H:   return "emm7h";


        case CV_REG_MM00:    return "mm00";  // do not change the order of these regs, first one must be even too
        case CV_REG_MM01:    return "mm01";
        case CV_REG_MM10:    return "mm10";
        case CV_REG_MM11:    return "mm11";
        case CV_REG_MM20:    return "mm20";
        case CV_REG_MM21:    return "mm21";
        case CV_REG_MM30:    return "mm30";
        case CV_REG_MM31:    return "mm31";
        case CV_REG_MM40:    return "mm40";
        case CV_REG_MM41:    return "mm41";
        case CV_REG_MM50:    return "mm50";
        case CV_REG_MM51:    return "mm51";
        case CV_REG_MM60:    return "mm60";
        case CV_REG_MM61:    return "mm61";
        case CV_REG_MM70:    return "mm70";
        case CV_REG_MM71:    return "mm71";
      }
      break;

      // registers for the 68K processors
    case CV_CFL_M68000:
    case CV_CFL_M68010:
    case CV_CFL_M68020:
    case CV_CFL_M68030:
    case CV_CFL_M68040:
      switch ( reg )
      {
        case CV_R68_D0:      return "D0";
        case CV_R68_D1:      return "D1";
        case CV_R68_D2:      return "D2";
        case CV_R68_D3:      return "D3";
        case CV_R68_D4:      return "D4";
        case CV_R68_D5:      return "D5";
        case CV_R68_D6:      return "D6";
        case CV_R68_D7:      return "D7";
        case CV_R68_A0:      return "A0";
        case CV_R68_A1:      return "A1";
        case CV_R68_A2:      return "A2";
        case CV_R68_A3:      return "A3";
        case CV_R68_A4:      return "A4";
        case CV_R68_A5:      return "A5";
        case CV_R68_A6:      return "A6";
        case CV_R68_A7:      return "A7";
        case CV_R68_CCR:     return "CCR";
        case CV_R68_SR:      return "SR";
        case CV_R68_USP:     return "USP";
        case CV_R68_MSP:     return "MSP";
        case CV_R68_SFC:     return "SFC";
        case CV_R68_DFC:     return "DFC";
        case CV_R68_CACR:    return "CACR";
        case CV_R68_VBR:     return "VBR";
        case CV_R68_CAAR:    return "CAAR";
        case CV_R68_ISP:     return "ISP";
        case CV_R68_PC:      return "PC";
        //reserved  27
        case CV_R68_FPCR:    return "FPCR";
        case CV_R68_FPSR:    return "FPSR";
        case CV_R68_FPIAR:   return "FPIAR";
        //reserved  31
        case CV_R68_FP0:     return "FP0";
        case CV_R68_FP1:     return "FP1";
        case CV_R68_FP2:     return "FP2";
        case CV_R68_FP3:     return "FP3";
        case CV_R68_FP4:     return "FP4";
        case CV_R68_FP5:     return "FP5";
        case CV_R68_FP6:     return "FP6";
        case CV_R68_FP7:     return "FP7";
        //reserved  40
        case CV_R68_MMUSR030:return "MMUSR030";
        case CV_R68_MMUSR:   return "MMUSR";
        case CV_R68_URP:     return "URP";
        case CV_R68_DTT0:    return "DTT0";
        case CV_R68_DTT1:    return "DTT1";
        case CV_R68_ITT0:    return "ITT0";
        case CV_R68_ITT1:    return "ITT1";
        //reserved  50
        case CV_R68_PSR:     return "PSR";
        case CV_R68_PCSR:    return "PCSR";
        case CV_R68_VAL:     return "VAL";
        case CV_R68_CRP:     return "CRP";
        case CV_R68_SRP:     return "SRP";
        case CV_R68_DRP:     return "DRP";
        case CV_R68_TC:      return "TC";
        case CV_R68_AC:      return "AC";
        case CV_R68_SCC:     return "SCC";
        case CV_R68_CAL:     return "CAL";
        case CV_R68_TT0:     return "TT0";
        case CV_R68_TT1:     return "TT1";
        //reserved  63
        case CV_R68_BAD0:    return "BAD0";
        case CV_R68_BAD1:    return "BAD1";
        case CV_R68_BAD2:    return "BAD2";
        case CV_R68_BAD3:    return "BAD3";
        case CV_R68_BAD4:    return "BAD4";
        case CV_R68_BAD5:    return "BAD5";
        case CV_R68_BAD6:    return "BAD6";
        case CV_R68_BAD7:    return "BAD7";
        case CV_R68_BAC0:    return "BAC0";
        case CV_R68_BAC1:    return "BAC1";
        case CV_R68_BAC2:    return "BAC2";
        case CV_R68_BAC3:    return "BAC3";
        case CV_R68_BAC4:    return "BAC4";
        case CV_R68_BAC5:    return "BAC5";
        case CV_R68_BAC6:    return "BAC6";
        case CV_R68_BAC7:    return "BAC7";
      }
      break;

    case CV_CFL_MIPS:
    case CV_CFL_MIPS16:
    case CV_CFL_MIPS32:
    case CV_CFL_MIPS64:
    case CV_CFL_MIPSI:
    case CV_CFL_MIPSII:
    case CV_CFL_MIPSIII:
    case CV_CFL_MIPSIV:
    case CV_CFL_MIPSV:
      switch ( reg )
      {
        // Register set for the MIPS 4000
        case CV_M4_NOREG:    return "NOREG";
        case CV_M4_IntZERO:  return "IntZERO";    /* CPU REGISTER */
        case CV_M4_IntAT:    return "IntAT";
        case CV_M4_IntV0:    return "IntV0";
        case CV_M4_IntV1:    return "IntV1";
        case CV_M4_IntA0:    return "IntA0";
        case CV_M4_IntA1:    return "IntA1";
        case CV_M4_IntA2:    return "IntA2";
        case CV_M4_IntA3:    return "IntA3";
        case CV_M4_IntT0:    return "IntT0";
        case CV_M4_IntT1:    return "IntT1";
        case CV_M4_IntT2:    return "IntT2";
        case CV_M4_IntT3:    return "IntT3";
        case CV_M4_IntT4:    return "IntT4";
        case CV_M4_IntT5:    return "IntT5";
        case CV_M4_IntT6:    return "IntT6";
        case CV_M4_IntT7:    return "IntT7";
        case CV_M4_IntS0:    return "IntS0";
        case CV_M4_IntS1:    return "IntS1";
        case CV_M4_IntS2:    return "IntS2";
        case CV_M4_IntS3:    return "IntS3";
        case CV_M4_IntS4:    return "IntS4";
        case CV_M4_IntS5:    return "IntS5";
        case CV_M4_IntS6:    return "IntS6";
        case CV_M4_IntS7:    return "IntS7";
        case CV_M4_IntT8:    return "IntT8";
        case CV_M4_IntT9:    return "IntT9";
        case CV_M4_IntKT0:   return "IntKT0";
        case CV_M4_IntKT1:   return "IntKT1";
        case CV_M4_IntGP:    return "IntGP";
        case CV_M4_IntSP:    return "IntSP";
        case CV_M4_IntS8:    return "IntS8";
        case CV_M4_IntRA:    return "IntRA";
        case CV_M4_IntLO:    return "IntLO";
        case CV_M4_IntHI:    return "IntHI";

        case CV_M4_Fir:
        case CV_M4_Psr:

        case CV_M4_FltF0:    return "FltF0";  /* Floating point registers */
        case CV_M4_FltF1:    return "FltF1";
        case CV_M4_FltF2:    return "FltF2";
        case CV_M4_FltF3:    return "FltF3";
        case CV_M4_FltF4:    return "FltF4";
        case CV_M4_FltF5:    return "FltF5";
        case CV_M4_FltF6:    return "FltF6";
        case CV_M4_FltF7:    return "FltF7";
        case CV_M4_FltF8:    return "FltF8";
        case CV_M4_FltF9:    return "FltF9";
        case CV_M4_FltF10:   return "FltF10";
        case CV_M4_FltF11:   return "FltF11";
        case CV_M4_FltF12:   return "FltF12";
        case CV_M4_FltF13:   return "FltF13";
        case CV_M4_FltF14:   return "FltF14";
        case CV_M4_FltF15:   return "FltF15";
        case CV_M4_FltF16:   return "FltF16";
        case CV_M4_FltF17:   return "FltF17";
        case CV_M4_FltF18:   return "FltF18";
        case CV_M4_FltF19:   return "FltF19";
        case CV_M4_FltF20:   return "FltF20";
        case CV_M4_FltF21:   return "FltF21";
        case CV_M4_FltF22:   return "FltF22";
        case CV_M4_FltF23:   return "FltF23";
        case CV_M4_FltF24:   return "FltF24";
        case CV_M4_FltF25:   return "FltF25";
        case CV_M4_FltF26:   return "FltF26";
        case CV_M4_FltF27:   return "FltF27";
        case CV_M4_FltF28:   return "FltF28";
        case CV_M4_FltF29:   return "FltF29";
        case CV_M4_FltF30:   return "FltF30";
        case CV_M4_FltF31:   return "FltF31";
        case CV_M4_FltFsr:   return "FltFsr";
      }
      break;

    case CV_CFL_ALPHA:
//    case CV_CFL_ALPHA_21064:
    case CV_CFL_ALPHA_21164:
    case CV_CFL_ALPHA_21164A:
    case CV_CFL_ALPHA_21264:
    case CV_CFL_ALPHA_21364:
      // Register set for the ALPHA AXP
      switch ( reg )
      {
        case CV_ALPHA_NOREG: return "NOREG";
        case CV_ALPHA_FltF0: return "FltF0";  // Floating point registers
        case CV_ALPHA_FltF1: return "FltF1";
        case CV_ALPHA_FltF2: return "FltF2";
        case CV_ALPHA_FltF3: return "FltF3";
        case CV_ALPHA_FltF4: return "FltF4";
        case CV_ALPHA_FltF5: return "FltF5";
        case CV_ALPHA_FltF6: return "FltF6";
        case CV_ALPHA_FltF7: return "FltF7";
        case CV_ALPHA_FltF8: return "FltF8";
        case CV_ALPHA_FltF9: return "FltF9";
        case CV_ALPHA_FltF10:return "FltF10";
        case CV_ALPHA_FltF11:return "FltF11";
        case CV_ALPHA_FltF12:return "FltF12";
        case CV_ALPHA_FltF13:return "FltF13";
        case CV_ALPHA_FltF14:return "FltF14";
        case CV_ALPHA_FltF15:return "FltF15";
        case CV_ALPHA_FltF16:return "FltF16";
        case CV_ALPHA_FltF17:return "FltF17";
        case CV_ALPHA_FltF18:return "FltF18";
        case CV_ALPHA_FltF19:return "FltF19";
        case CV_ALPHA_FltF20:return "FltF20";
        case CV_ALPHA_FltF21:return "FltF21";
        case CV_ALPHA_FltF22:return "FltF22";
        case CV_ALPHA_FltF23:return "FltF23";
        case CV_ALPHA_FltF24:return "FltF24";
        case CV_ALPHA_FltF25:return "FltF25";
        case CV_ALPHA_FltF26:return "FltF26";
        case CV_ALPHA_FltF27:return "FltF27";
        case CV_ALPHA_FltF28:return "FltF28";
        case CV_ALPHA_FltF29:return "FltF29";
        case CV_ALPHA_FltF30:return "FltF30";
        case CV_ALPHA_FltF31:return "FltF31";

        case CV_ALPHA_IntV0: return "IntV0";  // Integer registers
        case CV_ALPHA_IntT0: return "IntT0";
        case CV_ALPHA_IntT1: return "IntT1";
        case CV_ALPHA_IntT2: return "IntT2";
        case CV_ALPHA_IntT3: return "IntT3";
        case CV_ALPHA_IntT4: return "IntT4";
        case CV_ALPHA_IntT5: return "IntT5";
        case CV_ALPHA_IntT6: return "IntT6";
        case CV_ALPHA_IntT7: return "IntT7";
        case CV_ALPHA_IntS0: return "IntS0";
        case CV_ALPHA_IntS1: return "IntS1";
        case CV_ALPHA_IntS2: return "IntS2";
        case CV_ALPHA_IntS3: return "IntS3";
        case CV_ALPHA_IntS4: return "IntS4";
        case CV_ALPHA_IntS5: return "IntS5";
        case CV_ALPHA_IntFP: return "IntFP";
        case CV_ALPHA_IntA0: return "IntA0";
        case CV_ALPHA_IntA1: return "IntA1";
        case CV_ALPHA_IntA2: return "IntA2";
        case CV_ALPHA_IntA3: return "IntA3";
        case CV_ALPHA_IntA4: return "IntA4";
        case CV_ALPHA_IntA5: return "IntA5";
        case CV_ALPHA_IntT8: return "IntT8";
        case CV_ALPHA_IntT9: return "IntT9";
        case CV_ALPHA_IntT10:return "IntT10";
        case CV_ALPHA_IntT11:return "IntT11";
        case CV_ALPHA_IntRA: return "IntRA";
        case CV_ALPHA_IntT12:return "IntT12";
        case CV_ALPHA_IntAT: return "IntAT";
        case CV_ALPHA_IntGP: return "IntGP";
        case CV_ALPHA_IntSP: return "IntSP";
        case CV_ALPHA_IntZERO:return "IntZERO";

        case CV_ALPHA_Fpcr:  return "Fpcr"; // Control registers
        case CV_ALPHA_Fir:   return "Fir";
        case CV_ALPHA_Psr:   return "Psr";
        case CV_ALPHA_FltFsr:return "FltFsr";
        case CV_ALPHA_SoftFpcr:return "SoftFpcr";
      }
      break;

    case CV_CFL_PPC601:
    case CV_CFL_PPC603:
    case CV_CFL_PPC604:
    case CV_CFL_PPC620:
    case CV_CFL_PPCFP:
    case CV_CFL_PPCBE:
      // Register Set for Motorola/IBM PowerPC
      switch ( reg )
      {
        /*
        ** PowerPC General Registers ( User Level )
        */
        case CV_PPC_GPR0:    return "gpr0";
        case CV_PPC_GPR1:    return "gpr1";
        case CV_PPC_GPR2:    return "gpr2";
        case CV_PPC_GPR3:    return "gpr3";
        case CV_PPC_GPR4:    return "gpr4";
        case CV_PPC_GPR5:    return "gpr5";
        case CV_PPC_GPR6:    return "gpr6";
        case CV_PPC_GPR7:    return "gpr7";
        case CV_PPC_GPR8:    return "gpr8";
        case CV_PPC_GPR9:    return "gpr9";
        case CV_PPC_GPR10:   return "gpr10";
        case CV_PPC_GPR11:   return "gpr11";
        case CV_PPC_GPR12:   return "gpr12";
        case CV_PPC_GPR13:   return "gpr13";
        case CV_PPC_GPR14:   return "gpr14";
        case CV_PPC_GPR15:   return "gpr15";
        case CV_PPC_GPR16:   return "gpr16";
        case CV_PPC_GPR17:   return "gpr17";
        case CV_PPC_GPR18:   return "gpr18";
        case CV_PPC_GPR19:   return "gpr19";
        case CV_PPC_GPR20:   return "gpr20";
        case CV_PPC_GPR21:   return "gpr21";
        case CV_PPC_GPR22:   return "gpr22";
        case CV_PPC_GPR23:   return "gpr23";
        case CV_PPC_GPR24:   return "gpr24";
        case CV_PPC_GPR25:   return "gpr25";
        case CV_PPC_GPR26:   return "gpr26";
        case CV_PPC_GPR27:   return "gpr27";
        case CV_PPC_GPR28:   return "gpr28";
        case CV_PPC_GPR29:   return "gpr29";
        case CV_PPC_GPR30:   return "gpr30";
        case CV_PPC_GPR31:   return "gpr31";

        /*
        ** PowerPC Condition Register ( user level )
        */
        case CV_PPC_CR:      return "cr";
        case CV_PPC_CR0:     return "cr0";
        case CV_PPC_CR1:     return "cr1";
        case CV_PPC_CR2:     return "cr2";
        case CV_PPC_CR3:     return "cr3";
        case CV_PPC_CR4:     return "cr4";
        case CV_PPC_CR5:     return "cr5";
        case CV_PPC_CR6:     return "cr6";
        case CV_PPC_CR7:     return "cr7";

        /*
        ** PowerPC Floating Point Registers ( user Level )
        */
        case CV_PPC_FPR0:    return "fpr0";
        case CV_PPC_FPR1:    return "fpr1";
        case CV_PPC_FPR2:    return "fpr2";
        case CV_PPC_FPR3:    return "fpr3";
        case CV_PPC_FPR4:    return "fpr4";
        case CV_PPC_FPR5:    return "fpr5";
        case CV_PPC_FPR6:    return "fpr6";
        case CV_PPC_FPR7:    return "fpr7";
        case CV_PPC_FPR8:    return "fpr8";
        case CV_PPC_FPR9:    return "fpr9";
        case CV_PPC_FPR10:   return "fpr10";
        case CV_PPC_FPR11:   return "fpr11";
        case CV_PPC_FPR12:   return "fpr12";
        case CV_PPC_FPR13:   return "fpr13";
        case CV_PPC_FPR14:   return "fpr14";
        case CV_PPC_FPR15:   return "fpr15";
        case CV_PPC_FPR16:   return "fpr16";
        case CV_PPC_FPR17:   return "fpr17";
        case CV_PPC_FPR18:   return "fpr18";
        case CV_PPC_FPR19:   return "fpr19";
        case CV_PPC_FPR20:   return "fpr20";
        case CV_PPC_FPR21:   return "fpr21";
        case CV_PPC_FPR22:   return "fpr22";
        case CV_PPC_FPR23:   return "fpr23";
        case CV_PPC_FPR24:   return "fpr24";
        case CV_PPC_FPR25:   return "fpr25";
        case CV_PPC_FPR26:   return "fpr26";
        case CV_PPC_FPR27:   return "fpr27";
        case CV_PPC_FPR28:   return "fpr28";
        case CV_PPC_FPR29:   return "fpr29";
        case CV_PPC_FPR30:   return "fpr30";
        case CV_PPC_FPR31:   return "fpr31";

        /*
        ** PowerPC Floating Point Status and Control Register ( User Level )
        */
        case CV_PPC_FPSCR:   return "FPSCR";

        /*
        ** PowerPC Machine State Register ( Supervisor Level )
        */
        case CV_PPC_MSR:     return "msr";

        /*
        ** PowerPC Segment Registers ( Supervisor Level )
        */
        case CV_PPC_SR0:     return "sr0";
        case CV_PPC_SR1:     return "sr1";
        case CV_PPC_SR2:     return "sr2";
        case CV_PPC_SR3:     return "sr3";
        case CV_PPC_SR4:     return "sr4";
        case CV_PPC_SR5:     return "sr5";
        case CV_PPC_SR6:     return "sr6";
        case CV_PPC_SR7:     return "sr7";
        case CV_PPC_SR8:     return "sr8";
        case CV_PPC_SR9:     return "sr9";
        case CV_PPC_SR10:    return "sr10";
        case CV_PPC_SR11:    return "sr11";
        case CV_PPC_SR12:    return "sr12";
        case CV_PPC_SR13:    return "sr13";
        case CV_PPC_SR14:    return "sr14";
        case CV_PPC_SR15:    return "sr15";

        /*
        ** For all of the special purpose registers add 100 to the SPR# that the
        ** Motorola/IBM documentation gives with the exception of any imaginary
        ** registers.
        */

        /*
        ** PowerPC Special Purpose Registers ( User Level )
        */
        case CV_PPC_PC:      return "pc";// PC (imaginary register)

        case CV_PPC_MQ:      return "mq";// MPC601
        case CV_PPC_XER:     return "xer";
        case CV_PPC_RTCU:    return "rtcu";// MPC601
        case CV_PPC_RTCL:    return "rtcl";// MPC601
        case CV_PPC_LR:      return "lr";
        case CV_PPC_CTR:     return "ctr";

        case CV_PPC_COMPARE: return "compare";// part of XER (internal to the debugger only)
        case CV_PPC_COUNT:   return "count";// part of XER (internal to the debugger only)

        /*
        ** PowerPC Special Purpose Registers ( supervisor Level )
        */
        case CV_PPC_DSISR:   return "dsisr";
        case CV_PPC_DAR:     return "dar";
        case CV_PPC_DEC:     return "dec";
        case CV_PPC_SDR1:    return "sdr1";
        case CV_PPC_SRR0:    return "srr0";
        case CV_PPC_SRR1:    return "srr1";
        case CV_PPC_SPRG0:   return "sprg0";
        case CV_PPC_SPRG1:   return "sprg1";
        case CV_PPC_SPRG2:   return "sprg2";
        case CV_PPC_SPRG3:   return "sprg3";
        case CV_PPC_ASR:     return "asr";// 64-bit implementations only
        case CV_PPC_EAR:     return "ear";
        case CV_PPC_PVR:     return "pvr";
        case CV_PPC_BAT0U:   return "bat0u";
        case CV_PPC_BAT0L:   return "bat0l";
        case CV_PPC_BAT1U:   return "bat1u";
        case CV_PPC_BAT1L:   return "bat1l";
        case CV_PPC_BAT2U:   return "bat2u";
        case CV_PPC_BAT2L:   return "bat2l";
        case CV_PPC_BAT3U:   return "bat3u";
        case CV_PPC_BAT3L:   return "bat3l";
        case CV_PPC_DBAT0U:  return "dbat0u";
        case CV_PPC_DBAT0L:  return "dbat0l";
        case CV_PPC_DBAT1U:  return "dbat1u";
        case CV_PPC_DBAT1L:  return "dbat1l";
        case CV_PPC_DBAT2U:  return "dbat2u";
        case CV_PPC_DBAT2L:  return "dbat2l";
        case CV_PPC_DBAT3U:  return "dbat3u";
        case CV_PPC_DBAT3L:  return "dbat3l";

        /*
        ** PowerPC Special Purpose Registers implementation Dependent ( Supervisor Level )
        */

        /*
        ** Doesn't appear that IBM/Motorola has finished defining these.
        */

        case CV_PPC_PMR0:    return "pmr0";// MPC620,
        case CV_PPC_PMR1:    return "pmr1";// MPC620,
        case CV_PPC_PMR2:    return "pmr2";// MPC620,
        case CV_PPC_PMR3:    return "pmr3";// MPC620,
        case CV_PPC_PMR4:    return "pmr4";// MPC620,
        case CV_PPC_PMR5:    return "pmr5";// MPC620,
        case CV_PPC_PMR6:    return "pmr6";// MPC620,
        case CV_PPC_PMR7:    return "pmr7";// MPC620,
        case CV_PPC_PMR8:    return "pmr8";// MPC620,
        case CV_PPC_PMR9:    return "pmr9";// MPC620,
        case CV_PPC_PMR10:   return "pmr10";// MPC620,
        case CV_PPC_PMR11:   return "pmr11";// MPC620,
        case CV_PPC_PMR12:   return "pmr12";// MPC620,
        case CV_PPC_PMR13:   return "pmr13";// MPC620,
        case CV_PPC_PMR14:   return "pmr14";// MPC620,
        case CV_PPC_PMR15:   return "pmr15";// MPC620,

        case CV_PPC_DMISS:   return "dmiss";// MPC603
        case CV_PPC_DCMP:    return "dcmp";// MPC603
        case CV_PPC_HASH1:   return "hash1";// MPC603
        case CV_PPC_HASH2:   return "hash2";// MPC603
        case CV_PPC_IMISS:   return "imiss";// MPC603
        case CV_PPC_ICMP:    return "icmp";// MPC603
        case CV_PPC_RPA:     return "rpa";// MPC603

        case CV_PPC_HID0:    return "hid0";// MPC601, MPC603, MPC620
        case CV_PPC_HID1:    return "hid1";// MPC601
        case CV_PPC_HID2:    return "hid2";// MPC601, MPC603, MPC620 ( IABR )
        case CV_PPC_HID3:    return "hid3";// Not Defined
        case CV_PPC_HID4:    return "hid4";// Not Defined
        case CV_PPC_HID5:    return "hid5";// MPC601, MPC604, MPC620 ( DABR )
        case CV_PPC_HID6:    return "hid6";// Not Defined
        case CV_PPC_HID7:    return "hid7";// Not Defined
        case CV_PPC_HID8:    return "hid8";// MPC620 ( BUSCSR )
        case CV_PPC_HID9:    return "hid9";// MPC620 ( L2CSR )
        case CV_PPC_HID10:   return "hid10";// Not Defined
        case CV_PPC_HID11:   return "hid11";// Not Defined
        case CV_PPC_HID12:   return "hid12";// Not Defined
        case CV_PPC_HID13:   return "hid13";// MPC604 ( HCR )
        case CV_PPC_HID14:   return "hid14";// Not Defined
        case CV_PPC_HID15:   return "hid15";// MPC601, MPC604, MPC620 ( PIR )
      }
      break;

    //
    // JAVA VM registers
    //

    //    case CV_JAVA_PC:     return "PC";

    case CV_CFL_SH3:
    case CV_CFL_SH3E:
    case CV_CFL_SH3DSP:
    case CV_CFL_SH4:
      //
      // Register set for the Hitachi SH3
      //
      switch ( reg )
      {
        case CV_SH3_NOREG:   return "NOREG";

        case CV_SH3_IntR0:   return "IntR0";// CPU REGISTER
        case CV_SH3_IntR1:   return "IntR1";
        case CV_SH3_IntR2:   return "IntR2";
        case CV_SH3_IntR3:   return "IntR3";
        case CV_SH3_IntR4:   return "IntR4";
        case CV_SH3_IntR5:   return "IntR5";
        case CV_SH3_IntR6:   return "IntR6";
        case CV_SH3_IntR7:   return "IntR7";
        case CV_SH3_IntR8:   return "IntR8";
        case CV_SH3_IntR9:   return "IntR9";
        case CV_SH3_IntR10:  return "IntR10";
        case CV_SH3_IntR11:  return "IntR11";
        case CV_SH3_IntR12:  return "IntR12";
        case CV_SH3_IntR13:  return "IntR13";
        case CV_SH3_IntFp:   return "IntFp";
        case CV_SH3_IntSp:   return "IntSp";
        case CV_SH3_Gbr:     return "Gbr";
        case CV_SH3_Pr:      return "Pr";
        case CV_SH3_Mach:    return "Mach";
        case CV_SH3_Macl:    return "Macl";

        case CV_SH3_Pc:      return "Pc";
        case CV_SH3_Sr:      return "Sr";

        case CV_SH3_BarA:    return "BarA";
        case CV_SH3_BasrA:   return "BasrA";
        case CV_SH3_BamrA:   return "BamrA";
        case CV_SH3_BbrA:    return "BbrA";
        case CV_SH3_BarB:    return "BarB";
        case CV_SH3_BasrB:   return "BasrB";
        case CV_SH3_BamrB:   return "BamrB";
        case CV_SH3_BbrB:    return "BbrB";
        case CV_SH3_BdrB:    return "BdrB";
        case CV_SH3_BdmrB:   return "BdmrB";
        case CV_SH3_Brcr:    return "Brcr";

        //
        // Additional registers for Hitachi SH processors
        //

        case CV_SH_Fpscr:    return "Fpscr";// floating point status/control register
        case CV_SH_Fpul:     return "Fpul";// floating point communication register

        case CV_SH_FpR0:     return "FpR0";// Floating point registers
        case CV_SH_FpR1:     return "FpR1";
        case CV_SH_FpR2:     return "FpR2";
        case CV_SH_FpR3:     return "FpR3";
        case CV_SH_FpR4:     return "FpR4";
        case CV_SH_FpR5:     return "FpR5";
        case CV_SH_FpR6:     return "FpR6";
        case CV_SH_FpR7:     return "FpR7";
        case CV_SH_FpR8:     return "FpR8";
        case CV_SH_FpR9:     return "FpR9";
        case CV_SH_FpR10:    return "FpR10";
        case CV_SH_FpR11:    return "FpR11";
        case CV_SH_FpR12:    return "FpR12";
        case CV_SH_FpR13:    return "FpR13";
        case CV_SH_FpR14:    return "FpR14";
        case CV_SH_FpR15:    return "FpR15";

        case CV_SH_XFpR0:    return "XFpR0";
        case CV_SH_XFpR1:    return "XFpR1";
        case CV_SH_XFpR2:    return "XFpR2";
        case CV_SH_XFpR3:    return "XFpR3";
        case CV_SH_XFpR4:    return "XFpR4";
        case CV_SH_XFpR5:    return "XFpR5";
        case CV_SH_XFpR6:    return "XFpR6";
        case CV_SH_XFpR7:    return "XFpR7";
        case CV_SH_XFpR8:    return "XFpR8";
        case CV_SH_XFpR9:    return "XFpR9";
        case CV_SH_XFpR10:   return "XFpR10";
        case CV_SH_XFpR11:   return "XFpR11";
        case CV_SH_XFpR12:   return "XFpR12";
        case CV_SH_XFpR13:   return "XFpR13";
        case CV_SH_XFpR14:   return "XFpR14";
        case CV_SH_XFpR15:   return "XFpR15";
      }
      break;

    case CV_CFL_ARM3:
    case CV_CFL_ARM4:
    case CV_CFL_ARM4T:
    case CV_CFL_ARM5:
    case CV_CFL_ARM5T:
    case CV_CFL_ARM6:
    case CV_CFL_ARM_XMAC:
    case CV_CFL_ARM_WMMX:
    case CV_CFL_THUMB:
      //
      // Register set for the ARM processor.
      //
      switch ( reg )
      {
        case CV_ARM_NOREG:   return "noreg";
        case CV_ARM_R0:      return "r0";
        case CV_ARM_R1:      return "r1";
        case CV_ARM_R2:      return "r2";
        case CV_ARM_R3:      return "r3";
        case CV_ARM_R4:      return "r4";
        case CV_ARM_R5:      return "r5";
        case CV_ARM_R6:      return "r6";
        case CV_ARM_R7:      return "r7";
        case CV_ARM_R8:      return "r8";
        case CV_ARM_R9:      return "r9";
        case CV_ARM_R10:     return "r10";
        case CV_ARM_R11:     return "r11";// Frame pointer, if allocated
        case CV_ARM_R12:     return "r12";
        case CV_ARM_SP:      return "sp";// Stack pointer
        case CV_ARM_LR:      return "lr";// Link Register
        case CV_ARM_PC:      return "pc";// Program counter
        case CV_ARM_CPSR:    return "cpsr";// Current program status register
      }
      break;

    case CV_CFL_IA64:
//    case CV_CFL_IA64_1:
    case CV_CFL_IA64_2:
      //
      // Register set for Intel IA64
      //
      switch ( reg )
      {
        case CV_IA64_NOREG:  return "noreg";

        // Branch Registers

        case CV_IA64_Br0:    return "br0";
        case CV_IA64_Br1:    return "br1";
        case CV_IA64_Br2:    return "br2";
        case CV_IA64_Br3:    return "br3";
        case CV_IA64_Br4:    return "br4";
        case CV_IA64_Br5:    return "br5";
        case CV_IA64_Br6:    return "br6";
        case CV_IA64_Br7:    return "br7";

        // Predicate Registers

        case CV_IA64_P0:     return "p0";
        case CV_IA64_P1:     return "p1";
        case CV_IA64_P2:     return "p2";
        case CV_IA64_P3:     return "p3";
        case CV_IA64_P4:     return "p4";
        case CV_IA64_P5:     return "p5";
        case CV_IA64_P6:     return "p6";
        case CV_IA64_P7:     return "p7";
        case CV_IA64_P8:     return "p8";
        case CV_IA64_P9:     return "p9";
        case CV_IA64_P10:    return "p10";
        case CV_IA64_P11:    return "p11";
        case CV_IA64_P12:    return "p12";
        case CV_IA64_P13:    return "p13";
        case CV_IA64_P14:    return "p14";
        case CV_IA64_P15:    return "p15";
        case CV_IA64_P16:    return "p16";
        case CV_IA64_P17:    return "p17";
        case CV_IA64_P18:    return "p18";
        case CV_IA64_P19:    return "p19";
        case CV_IA64_P20:    return "p20";
        case CV_IA64_P21:    return "p21";
        case CV_IA64_P22:    return "p22";
        case CV_IA64_P23:    return "p23";
        case CV_IA64_P24:    return "p24";
        case CV_IA64_P25:    return "p25";
        case CV_IA64_P26:    return "p26";
        case CV_IA64_P27:    return "p27";
        case CV_IA64_P28:    return "p28";
        case CV_IA64_P29:    return "p29";
        case CV_IA64_P30:    return "p30";
        case CV_IA64_P31:    return "p31";
        case CV_IA64_P32:    return "p32";
        case CV_IA64_P33:    return "p33";
        case CV_IA64_P34:    return "p34";
        case CV_IA64_P35:    return "p35";
        case CV_IA64_P36:    return "p36";
        case CV_IA64_P37:    return "p37";
        case CV_IA64_P38:    return "p38";
        case CV_IA64_P39:    return "p39";
        case CV_IA64_P40:    return "p40";
        case CV_IA64_P41:    return "p41";
        case CV_IA64_P42:    return "p42";
        case CV_IA64_P43:    return "p43";
        case CV_IA64_P44:    return "p44";
        case CV_IA64_P45:    return "p45";
        case CV_IA64_P46:    return "p46";
        case CV_IA64_P47:    return "p47";
        case CV_IA64_P48:    return "p48";
        case CV_IA64_P49:    return "p49";
        case CV_IA64_P50:    return "p50";
        case CV_IA64_P51:    return "p51";
        case CV_IA64_P52:    return "p52";
        case CV_IA64_P53:    return "p53";
        case CV_IA64_P54:    return "p54";
        case CV_IA64_P55:    return "p55";
        case CV_IA64_P56:    return "p56";
        case CV_IA64_P57:    return "p57";
        case CV_IA64_P58:    return "p58";
        case CV_IA64_P59:    return "p59";
        case CV_IA64_P60:    return "p60";
        case CV_IA64_P61:    return "p61";
        case CV_IA64_P62:    return "p62";
        case CV_IA64_P63:    return "p63";

        case CV_IA64_Preds:  return "Preds";

        // Banked General Registers

        case CV_IA64_IntH0:  return "IntH0";
        case CV_IA64_IntH1:  return "IntH1";
        case CV_IA64_IntH2:  return "IntH2";
        case CV_IA64_IntH3:  return "IntH3";
        case CV_IA64_IntH4:  return "IntH4";
        case CV_IA64_IntH5:  return "IntH5";
        case CV_IA64_IntH6:  return "IntH6";
        case CV_IA64_IntH7:  return "IntH7";
        case CV_IA64_IntH8:  return "IntH8";
        case CV_IA64_IntH9:  return "IntH9";
        case CV_IA64_IntH10: return "IntH10";
        case CV_IA64_IntH11: return "IntH11";
        case CV_IA64_IntH12: return "IntH12";
        case CV_IA64_IntH13: return "IntH13";
        case CV_IA64_IntH14: return "IntH14";
        case CV_IA64_IntH15: return "IntH15";

        // Special Registers

        case CV_IA64_Ip:     return "Ip";
        case CV_IA64_Umask:  return "Umask";
        case CV_IA64_Cfm:    return "Cfm";
        case CV_IA64_Psr:    return "Psr";

        // Banked General Registers

        case CV_IA64_Nats:   return "Nats";
        case CV_IA64_Nats2:  return "Nats2";
        case CV_IA64_Nats3:  return "Nats3";

        // General-Purpose Registers

        // Integer registers
        case CV_IA64_IntR0:  return "IntR0";
        case CV_IA64_IntR1:  return "IntR1";
        case CV_IA64_IntR2:  return "IntR2";
        case CV_IA64_IntR3:  return "IntR3";
        case CV_IA64_IntR4:  return "IntR4";
        case CV_IA64_IntR5:  return "IntR5";
        case CV_IA64_IntR6:  return "IntR6";
        case CV_IA64_IntR7:  return "IntR7";
        case CV_IA64_IntR8:  return "IntR8";
        case CV_IA64_IntR9:  return "IntR9";
        case CV_IA64_IntR10: return "IntR10";
        case CV_IA64_IntR11: return "IntR11";
        case CV_IA64_IntR12: return "IntR12";
        case CV_IA64_IntR13: return "IntR13";
        case CV_IA64_IntR14: return "IntR14";
        case CV_IA64_IntR15: return "IntR15";
        case CV_IA64_IntR16: return "IntR16";
        case CV_IA64_IntR17: return "IntR17";
        case CV_IA64_IntR18: return "IntR18";
        case CV_IA64_IntR19: return "IntR19";
        case CV_IA64_IntR20: return "IntR20";
        case CV_IA64_IntR21: return "IntR21";
        case CV_IA64_IntR22: return "IntR22";
        case CV_IA64_IntR23: return "IntR23";
        case CV_IA64_IntR24: return "IntR24";
        case CV_IA64_IntR25: return "IntR25";
        case CV_IA64_IntR26: return "IntR26";
        case CV_IA64_IntR27: return "IntR27";
        case CV_IA64_IntR28: return "IntR28";
        case CV_IA64_IntR29: return "IntR29";
        case CV_IA64_IntR30: return "IntR30";
        case CV_IA64_IntR31: return "IntR31";

        // Register Stack
        case CV_IA64_IntR32: return "IntR32";
        case CV_IA64_IntR33: return "IntR33";
        case CV_IA64_IntR34: return "IntR34";
        case CV_IA64_IntR35: return "IntR35";
        case CV_IA64_IntR36: return "IntR36";
        case CV_IA64_IntR37: return "IntR37";
        case CV_IA64_IntR38: return "IntR38";
        case CV_IA64_IntR39: return "IntR39";
        case CV_IA64_IntR40: return "IntR40";
        case CV_IA64_IntR41: return "IntR41";
        case CV_IA64_IntR42: return "IntR42";
        case CV_IA64_IntR43: return "IntR43";
        case CV_IA64_IntR44: return "IntR44";
        case CV_IA64_IntR45: return "IntR45";
        case CV_IA64_IntR46: return "IntR46";
        case CV_IA64_IntR47: return "IntR47";
        case CV_IA64_IntR48: return "IntR48";
        case CV_IA64_IntR49: return "IntR49";
        case CV_IA64_IntR50: return "IntR50";
        case CV_IA64_IntR51: return "IntR51";
        case CV_IA64_IntR52: return "IntR52";
        case CV_IA64_IntR53: return "IntR53";
        case CV_IA64_IntR54: return "IntR54";
        case CV_IA64_IntR55: return "IntR55";
        case CV_IA64_IntR56: return "IntR56";
        case CV_IA64_IntR57: return "IntR57";
        case CV_IA64_IntR58: return "IntR58";
        case CV_IA64_IntR59: return "IntR59";
        case CV_IA64_IntR60: return "IntR60";
        case CV_IA64_IntR61: return "IntR61";
        case CV_IA64_IntR62: return "IntR62";
        case CV_IA64_IntR63: return "IntR63";
        case CV_IA64_IntR64: return "IntR64";
        case CV_IA64_IntR65: return "IntR65";
        case CV_IA64_IntR66: return "IntR66";
        case CV_IA64_IntR67: return "IntR67";
        case CV_IA64_IntR68: return "IntR68";
        case CV_IA64_IntR69: return "IntR69";
        case CV_IA64_IntR70: return "IntR70";
        case CV_IA64_IntR71: return "IntR71";
        case CV_IA64_IntR72: return "IntR72";
        case CV_IA64_IntR73: return "IntR73";
        case CV_IA64_IntR74: return "IntR74";
        case CV_IA64_IntR75: return "IntR75";
        case CV_IA64_IntR76: return "IntR76";
        case CV_IA64_IntR77: return "IntR77";
        case CV_IA64_IntR78: return "IntR78";
        case CV_IA64_IntR79: return "IntR79";
        case CV_IA64_IntR80: return "IntR80";
        case CV_IA64_IntR81: return "IntR81";
        case CV_IA64_IntR82: return "IntR82";
        case CV_IA64_IntR83: return "IntR83";
        case CV_IA64_IntR84: return "IntR84";
        case CV_IA64_IntR85: return "IntR85";
        case CV_IA64_IntR86: return "IntR86";
        case CV_IA64_IntR87: return "IntR87";
        case CV_IA64_IntR88: return "IntR88";
        case CV_IA64_IntR89: return "IntR89";
        case CV_IA64_IntR90: return "IntR90";
        case CV_IA64_IntR91: return "IntR91";
        case CV_IA64_IntR92: return "IntR92";
        case CV_IA64_IntR93: return "IntR93";
        case CV_IA64_IntR94: return "IntR94";
        case CV_IA64_IntR95: return "IntR95";
        case CV_IA64_IntR96: return "IntR96";
        case CV_IA64_IntR97: return "IntR97";
        case CV_IA64_IntR98: return "IntR98";
        case CV_IA64_IntR99: return "IntR99";
        case CV_IA64_IntR100:return "IntR100";
        case CV_IA64_IntR101:return "IntR101";
        case CV_IA64_IntR102:return "IntR102";
        case CV_IA64_IntR103:return "IntR103";
        case CV_IA64_IntR104:return "IntR104";
        case CV_IA64_IntR105:return "IntR105";
        case CV_IA64_IntR106:return "IntR106";
        case CV_IA64_IntR107:return "IntR107";
        case CV_IA64_IntR108:return "IntR108";
        case CV_IA64_IntR109:return "IntR109";
        case CV_IA64_IntR110:return "IntR110";
        case CV_IA64_IntR111:return "IntR111";
        case CV_IA64_IntR112:return "IntR112";
        case CV_IA64_IntR113:return "IntR113";
        case CV_IA64_IntR114:return "IntR114";
        case CV_IA64_IntR115:return "IntR115";
        case CV_IA64_IntR116:return "IntR116";
        case CV_IA64_IntR117:return "IntR117";
        case CV_IA64_IntR118:return "IntR118";
        case CV_IA64_IntR119:return "IntR119";
        case CV_IA64_IntR120:return "IntR120";
        case CV_IA64_IntR121:return "IntR121";
        case CV_IA64_IntR122:return "IntR122";
        case CV_IA64_IntR123:return "IntR123";
        case CV_IA64_IntR124:return "IntR124";
        case CV_IA64_IntR125:return "IntR125";
        case CV_IA64_IntR126:return "IntR126";
        case CV_IA64_IntR127:return "IntR127";

        // Floating-Point Registers

        // Low Floating Point Registers
        case CV_IA64_FltF0:  return "FltF0";
        case CV_IA64_FltF1:  return "FltF1";
        case CV_IA64_FltF2:  return "FltF2";
        case CV_IA64_FltF3:  return "FltF3";
        case CV_IA64_FltF4:  return "FltF4";
        case CV_IA64_FltF5:  return "FltF5";
        case CV_IA64_FltF6:  return "FltF6";
        case CV_IA64_FltF7:  return "FltF7";
        case CV_IA64_FltF8:  return "FltF8";
        case CV_IA64_FltF9:  return "FltF9";
        case CV_IA64_FltF10: return "FltF10";
        case CV_IA64_FltF11: return "FltF11";
        case CV_IA64_FltF12: return "FltF12";
        case CV_IA64_FltF13: return "FltF13";
        case CV_IA64_FltF14: return "FltF14";
        case CV_IA64_FltF15: return "FltF15";
        case CV_IA64_FltF16: return "FltF16";
        case CV_IA64_FltF17: return "FltF17";
        case CV_IA64_FltF18: return "FltF18";
        case CV_IA64_FltF19: return "FltF19";
        case CV_IA64_FltF20: return "FltF20";
        case CV_IA64_FltF21: return "FltF21";
        case CV_IA64_FltF22: return "FltF22";
        case CV_IA64_FltF23: return "FltF23";
        case CV_IA64_FltF24: return "FltF24";
        case CV_IA64_FltF25: return "FltF25";
        case CV_IA64_FltF26: return "FltF26";
        case CV_IA64_FltF27: return "FltF27";
        case CV_IA64_FltF28: return "FltF28";
        case CV_IA64_FltF29: return "FltF29";
        case CV_IA64_FltF30: return "FltF30";
        case CV_IA64_FltF31: return "FltF31";

        // High Floating Point Registers
        case CV_IA64_FltF32: return "FltF32";
        case CV_IA64_FltF33: return "FltF33";
        case CV_IA64_FltF34: return "FltF34";
        case CV_IA64_FltF35: return "FltF35";
        case CV_IA64_FltF36: return "FltF36";
        case CV_IA64_FltF37: return "FltF37";
        case CV_IA64_FltF38: return "FltF38";
        case CV_IA64_FltF39: return "FltF39";
        case CV_IA64_FltF40: return "FltF40";
        case CV_IA64_FltF41: return "FltF41";
        case CV_IA64_FltF42: return "FltF42";
        case CV_IA64_FltF43: return "FltF43";
        case CV_IA64_FltF44: return "FltF44";
        case CV_IA64_FltF45: return "FltF45";
        case CV_IA64_FltF46: return "FltF46";
        case CV_IA64_FltF47: return "FltF47";
        case CV_IA64_FltF48: return "FltF48";
        case CV_IA64_FltF49: return "FltF49";
        case CV_IA64_FltF50: return "FltF50";
        case CV_IA64_FltF51: return "FltF51";
        case CV_IA64_FltF52: return "FltF52";
        case CV_IA64_FltF53: return "FltF53";
        case CV_IA64_FltF54: return "FltF54";
        case CV_IA64_FltF55: return "FltF55";
        case CV_IA64_FltF56: return "FltF56";
        case CV_IA64_FltF57: return "FltF57";
        case CV_IA64_FltF58: return "FltF58";
        case CV_IA64_FltF59: return "FltF59";
        case CV_IA64_FltF60: return "FltF60";
        case CV_IA64_FltF61: return "FltF61";
        case CV_IA64_FltF62: return "FltF62";
        case CV_IA64_FltF63: return "FltF63";
        case CV_IA64_FltF64: return "FltF64";
        case CV_IA64_FltF65: return "FltF65";
        case CV_IA64_FltF66: return "FltF66";
        case CV_IA64_FltF67: return "FltF67";
        case CV_IA64_FltF68: return "FltF68";
        case CV_IA64_FltF69: return "FltF69";
        case CV_IA64_FltF70: return "FltF70";
        case CV_IA64_FltF71: return "FltF71";
        case CV_IA64_FltF72: return "FltF72";
        case CV_IA64_FltF73: return "FltF73";
        case CV_IA64_FltF74: return "FltF74";
        case CV_IA64_FltF75: return "FltF75";
        case CV_IA64_FltF76: return "FltF76";
        case CV_IA64_FltF77: return "FltF77";
        case CV_IA64_FltF78: return "FltF78";
        case CV_IA64_FltF79: return "FltF79";
        case CV_IA64_FltF80: return "FltF80";
        case CV_IA64_FltF81: return "FltF81";
        case CV_IA64_FltF82: return "FltF82";
        case CV_IA64_FltF83: return "FltF83";
        case CV_IA64_FltF84: return "FltF84";
        case CV_IA64_FltF85: return "FltF85";
        case CV_IA64_FltF86: return "FltF86";
        case CV_IA64_FltF87: return "FltF87";
        case CV_IA64_FltF88: return "FltF88";
        case CV_IA64_FltF89: return "FltF89";
        case CV_IA64_FltF90: return "FltF90";
        case CV_IA64_FltF91: return "FltF91";
        case CV_IA64_FltF92: return "FltF92";
        case CV_IA64_FltF93: return "FltF93";
        case CV_IA64_FltF94: return "FltF94";
        case CV_IA64_FltF95: return "FltF95";
        case CV_IA64_FltF96: return "FltF96";
        case CV_IA64_FltF97: return "FltF97";
        case CV_IA64_FltF98: return "FltF98";
        case CV_IA64_FltF99: return "FltF99";
        case CV_IA64_FltF100:return "FltF100";
        case CV_IA64_FltF101:return "FltF101";
        case CV_IA64_FltF102:return "FltF102";
        case CV_IA64_FltF103:return "FltF103";
        case CV_IA64_FltF104:return "FltF104";
        case CV_IA64_FltF105:return "FltF105";
        case CV_IA64_FltF106:return "FltF106";
        case CV_IA64_FltF107:return "FltF107";
        case CV_IA64_FltF108:return "FltF108";
        case CV_IA64_FltF109:return "FltF109";
        case CV_IA64_FltF110:return "FltF110";
        case CV_IA64_FltF111:return "FltF111";
        case CV_IA64_FltF112:return "FltF112";
        case CV_IA64_FltF113:return "FltF113";
        case CV_IA64_FltF114:return "FltF114";
        case CV_IA64_FltF115:return "FltF115";
        case CV_IA64_FltF116:return "FltF116";
        case CV_IA64_FltF117:return "FltF117";
        case CV_IA64_FltF118:return "FltF118";
        case CV_IA64_FltF119:return "FltF119";
        case CV_IA64_FltF120:return "FltF120";
        case CV_IA64_FltF121:return "FltF121";
        case CV_IA64_FltF122:return "FltF122";
        case CV_IA64_FltF123:return "FltF123";
        case CV_IA64_FltF124:return "FltF124";
        case CV_IA64_FltF125:return "FltF125";
        case CV_IA64_FltF126:return "FltF126";
        case CV_IA64_FltF127:return "FltF127";

        // Application Registers

        case CV_IA64_ApKR0:  return "ApKR0";
        case CV_IA64_ApKR1:  return "ApKR1";
        case CV_IA64_ApKR2:  return "ApKR2";
        case CV_IA64_ApKR3:  return "ApKR3";
        case CV_IA64_ApKR4:  return "ApKR4";
        case CV_IA64_ApKR5:  return "ApKR5";
        case CV_IA64_ApKR6:  return "ApKR6";
        case CV_IA64_ApKR7:  return "ApKR7";
        case CV_IA64_AR8:    return "AR8";
        case CV_IA64_AR9:    return "AR9";
        case CV_IA64_AR10:   return "AR10";
        case CV_IA64_AR11:   return "AR11";
        case CV_IA64_AR12:   return "AR12";
        case CV_IA64_AR13:   return "AR13";
        case CV_IA64_AR14:   return "AR14";
        case CV_IA64_AR15:   return "AR15";
        case CV_IA64_RsRSC:  return "RsRSC";
        case CV_IA64_RsBSP:  return "RsBSP";
        case CV_IA64_RsBSPSTORE:return "RsBSPSTORE";
        case CV_IA64_RsRNAT: return "rsrnat";
        case CV_IA64_AR20:   return "ar20";
        case CV_IA64_StFCR:  return "stfcr";
        case CV_IA64_AR22:   return "ar22";
        case CV_IA64_AR23:   return "ar23";
        case CV_IA64_EFLAG:  return "eflag";
        case CV_IA64_CSD:    return "csd";
        case CV_IA64_SSD:    return "ssd";
        case CV_IA64_CFLG:   return "cflg";
        case CV_IA64_StFSR:  return "stfsr";
        case CV_IA64_StFIR:  return "stfir";
        case CV_IA64_StFDR:  return "stfdr";
        case CV_IA64_AR31:   return "ar31";
        case CV_IA64_ApCCV:  return "apccv";
        case CV_IA64_AR33:   return "ar33";
        case CV_IA64_AR34:   return "ar34";
        case CV_IA64_AR35:   return "ar35";
        case CV_IA64_ApUNAT: return "apunat";
        case CV_IA64_AR37:   return "ar37";
        case CV_IA64_AR38:   return "ar38";
        case CV_IA64_AR39:   return "ar39";
        case CV_IA64_StFPSR: return "stfpsr";
        case CV_IA64_AR41:   return "ar41";
        case CV_IA64_AR42:   return "ar42";
        case CV_IA64_AR43:   return "ar43";
        case CV_IA64_ApITC:  return "apitc";
        case CV_IA64_AR45:   return "ar45";
        case CV_IA64_AR46:   return "ar46";
        case CV_IA64_AR47:   return "ar47";
        case CV_IA64_AR48:   return "ar48";
        case CV_IA64_AR49:   return "ar49";
        case CV_IA64_AR50:   return "ar50";
        case CV_IA64_AR51:   return "ar51";
        case CV_IA64_AR52:   return "ar52";
        case CV_IA64_AR53:   return "ar53";
        case CV_IA64_AR54:   return "ar54";
        case CV_IA64_AR55:   return "ar55";
        case CV_IA64_AR56:   return "ar56";
        case CV_IA64_AR57:   return "ar57";
        case CV_IA64_AR58:   return "ar58";
        case CV_IA64_AR59:   return "ar59";
        case CV_IA64_AR60:   return "ar60";
        case CV_IA64_AR61:   return "ar61";
        case CV_IA64_AR62:   return "ar62";
        case CV_IA64_AR63:   return "ar63";
        case CV_IA64_RsPFS:  return "rspfs";
        case CV_IA64_ApLC:   return "aplc";
        case CV_IA64_ApEC:   return "apec";
        case CV_IA64_AR67:   return "ar67";
        case CV_IA64_AR68:   return "ar68";
        case CV_IA64_AR69:   return "ar69";
        case CV_IA64_AR70:   return "ar70";
        case CV_IA64_AR71:   return "ar71";
        case CV_IA64_AR72:   return "ar72";
        case CV_IA64_AR73:   return "ar73";
        case CV_IA64_AR74:   return "ar74";
        case CV_IA64_AR75:   return "ar75";
        case CV_IA64_AR76:   return "ar76";
        case CV_IA64_AR77:   return "ar77";
        case CV_IA64_AR78:   return "ar78";
        case CV_IA64_AR79:   return "ar79";
        case CV_IA64_AR80:   return "ar80";
        case CV_IA64_AR81:   return "ar81";
        case CV_IA64_AR82:   return "ar82";
        case CV_IA64_AR83:   return "ar83";
        case CV_IA64_AR84:   return "ar84";
        case CV_IA64_AR85:   return "ar85";
        case CV_IA64_AR86:   return "ar86";
        case CV_IA64_AR87:   return "ar87";
        case CV_IA64_AR88:   return "ar88";
        case CV_IA64_AR89:   return "ar89";
        case CV_IA64_AR90:   return "ar90";
        case CV_IA64_AR91:   return "ar91";
        case CV_IA64_AR92:   return "ar92";
        case CV_IA64_AR93:   return "ar93";
        case CV_IA64_AR94:   return "ar94";
        case CV_IA64_AR95:   return "ar95";
        case CV_IA64_AR96:   return "ar96";
        case CV_IA64_AR97:   return "ar97";
        case CV_IA64_AR98:   return "ar98";
        case CV_IA64_AR99:   return "ar99";
        case CV_IA64_AR100:  return "ar100";
        case CV_IA64_AR101:  return "ar101";
        case CV_IA64_AR102:  return "ar102";
        case CV_IA64_AR103:  return "ar103";
        case CV_IA64_AR104:  return "ar104";
        case CV_IA64_AR105:  return "ar105";
        case CV_IA64_AR106:  return "ar106";
        case CV_IA64_AR107:  return "ar107";
        case CV_IA64_AR108:  return "ar108";
        case CV_IA64_AR109:  return "ar109";
        case CV_IA64_AR110:  return "ar110";
        case CV_IA64_AR111:  return "ar111";
        case CV_IA64_AR112:  return "ar112";
        case CV_IA64_AR113:  return "ar113";
        case CV_IA64_AR114:  return "ar114";
        case CV_IA64_AR115:  return "ar115";
        case CV_IA64_AR116:  return "ar116";
        case CV_IA64_AR117:  return "ar117";
        case CV_IA64_AR118:  return "ar118";
        case CV_IA64_AR119:  return "ar119";
        case CV_IA64_AR120:  return "ar120";
        case CV_IA64_AR121:  return "ar121";
        case CV_IA64_AR122:  return "ar122";
        case CV_IA64_AR123:  return "ar123";
        case CV_IA64_AR124:  return "ar124";
        case CV_IA64_AR125:  return "ar125";
        case CV_IA64_AR126:  return "ar126";
        case CV_IA64_AR127:  return "ar127";

        // CPUID Registers

        case CV_IA64_CPUID0: return "cpuid0";
        case CV_IA64_CPUID1: return "cpuid1";
        case CV_IA64_CPUID2: return "cpuid2";
        case CV_IA64_CPUID3: return "cpuid3";
        case CV_IA64_CPUID4: return "cpuid4";

        // Control Registers

        case CV_IA64_ApDCR:  return "apdcr";
        case CV_IA64_ApITM:  return "apitm";
        case CV_IA64_ApIVA:  return "apiva";
        case CV_IA64_CR3:    return "cr3";
        case CV_IA64_CR4:    return "cr4";
        case CV_IA64_CR5:    return "cr5";
        case CV_IA64_CR6:    return "cr6";
        case CV_IA64_CR7:    return "cr7";
        case CV_IA64_ApPTA:  return "appta";
        case CV_IA64_ApGPTA: return "apgpta";
        case CV_IA64_CR10:   return "cr10";
        case CV_IA64_CR11:   return "cr11";
        case CV_IA64_CR12:   return "cr12";
        case CV_IA64_CR13:   return "cr13";
        case CV_IA64_CR14:   return "cr14";
        case CV_IA64_CR15:   return "cr15";
        case CV_IA64_StIPSR: return "stipsr";
        case CV_IA64_StISR:  return "stisr";
        case CV_IA64_CR18:   return "cr18";
        case CV_IA64_StIIP:  return "stiip";
        case CV_IA64_StIFA:  return "stifa";
        case CV_IA64_StITIR: return "stitir";
        case CV_IA64_StIIPA: return "stiipa";
        case CV_IA64_StIFS:  return "stifs";
        case CV_IA64_StIIM:  return "stiim";
        case CV_IA64_StIHA:  return "stiha";
        case CV_IA64_CR26:   return "cr26";
        case CV_IA64_CR27:   return "cr27";
        case CV_IA64_CR28:   return "cr28";
        case CV_IA64_CR29:   return "cr29";
        case CV_IA64_CR30:   return "cr30";
        case CV_IA64_CR31:   return "cr31";
        case CV_IA64_CR32:   return "cr32";
        case CV_IA64_CR33:   return "cr33";
        case CV_IA64_CR34:   return "cr34";
        case CV_IA64_CR35:   return "cr35";
        case CV_IA64_CR36:   return "cr36";
        case CV_IA64_CR37:   return "cr37";
        case CV_IA64_CR38:   return "cr38";
        case CV_IA64_CR39:   return "cr39";
        case CV_IA64_CR40:   return "cr40";
        case CV_IA64_CR41:   return "cr41";
        case CV_IA64_CR42:   return "cr42";
        case CV_IA64_CR43:   return "cr43";
        case CV_IA64_CR44:   return "cr44";
        case CV_IA64_CR45:   return "cr45";
        case CV_IA64_CR46:   return "cr46";
        case CV_IA64_CR47:   return "cr47";
        case CV_IA64_CR48:   return "cr48";
        case CV_IA64_CR49:   return "cr49";
        case CV_IA64_CR50:   return "cr50";
        case CV_IA64_CR51:   return "cr51";
        case CV_IA64_CR52:   return "cr52";
        case CV_IA64_CR53:   return "cr53";
        case CV_IA64_CR54:   return "cr54";
        case CV_IA64_CR55:   return "cr55";
        case CV_IA64_CR56:   return "cr56";
        case CV_IA64_CR57:   return "cr57";
        case CV_IA64_CR58:   return "cr58";
        case CV_IA64_CR59:   return "cr59";
        case CV_IA64_CR60:   return "cr60";
        case CV_IA64_CR61:   return "cr61";
        case CV_IA64_CR62:   return "cr62";
        case CV_IA64_CR63:   return "cr63";
        case CV_IA64_SaLID:  return "salid";
        case CV_IA64_SaIVR:  return "saivr";
        case CV_IA64_SaTPR:  return "satpr";
        case CV_IA64_SaEOI:  return "saeoi";
        case CV_IA64_SaIRR0: return "sairr0";
        case CV_IA64_SaIRR1: return "sairr1";
        case CV_IA64_SaIRR2: return "sairr2";
        case CV_IA64_SaIRR3: return "sairr3";
        case CV_IA64_SaITV:  return "saitv";
        case CV_IA64_SaPMV:  return "sapmv";
        case CV_IA64_SaCMCV: return "sacmcv";
        case CV_IA64_CR75:   return "cr75";
        case CV_IA64_CR76:   return "cr76";
        case CV_IA64_CR77:   return "cr77";
        case CV_IA64_CR78:   return "cr78";
        case CV_IA64_CR79:   return "cr79";
        case CV_IA64_SaLRR0: return "salrr0";
        case CV_IA64_SaLRR1: return "salrr1";
        case CV_IA64_CR82:   return "cr82";
        case CV_IA64_CR83:   return "cr83";
        case CV_IA64_CR84:   return "cr84";
        case CV_IA64_CR85:   return "cr85";
        case CV_IA64_CR86:   return "cr86";
        case CV_IA64_CR87:   return "cr87";
        case CV_IA64_CR88:   return "cr88";
        case CV_IA64_CR89:   return "cr89";
        case CV_IA64_CR90:   return "cr90";
        case CV_IA64_CR91:   return "cr91";
        case CV_IA64_CR92:   return "cr92";
        case CV_IA64_CR93:   return "cr93";
        case CV_IA64_CR94:   return "cr94";
        case CV_IA64_CR95:   return "cr95";
        case CV_IA64_CR96:   return "cr96";
        case CV_IA64_CR97:   return "cr97";
        case CV_IA64_CR98:   return "cr98";
        case CV_IA64_CR99:   return "cr99";
        case CV_IA64_CR100:  return "cr100";
        case CV_IA64_CR101:  return "cr101";
        case CV_IA64_CR102:  return "cr102";
        case CV_IA64_CR103:  return "cr103";
        case CV_IA64_CR104:  return "cr104";
        case CV_IA64_CR105:  return "cr105";
        case CV_IA64_CR106:  return "cr106";
        case CV_IA64_CR107:  return "cr107";
        case CV_IA64_CR108:  return "cr108";
        case CV_IA64_CR109:  return "cr109";
        case CV_IA64_CR110:  return "cr110";
        case CV_IA64_CR111:  return "cr111";
        case CV_IA64_CR112:  return "cr112";
        case CV_IA64_CR113:  return "cr113";
        case CV_IA64_CR114:  return "cr114";
        case CV_IA64_CR115:  return "cr115";
        case CV_IA64_CR116:  return "cr116";
        case CV_IA64_CR117:  return "cr117";
        case CV_IA64_CR118:  return "cr118";
        case CV_IA64_CR119:  return "cr119";
        case CV_IA64_CR120:  return "cr120";
        case CV_IA64_CR121:  return "cr121";
        case CV_IA64_CR122:  return "cr122";
        case CV_IA64_CR123:  return "cr123";
        case CV_IA64_CR124:  return "cr124";
        case CV_IA64_CR125:  return "cr125";
        case CV_IA64_CR126:  return "cr126";
        case CV_IA64_CR127:  return "cr127";

        // Protection Key Registers

        case CV_IA64_Pkr0:   return "pkr0";
        case CV_IA64_Pkr1:   return "pkr1";
        case CV_IA64_Pkr2:   return "pkr2";
        case CV_IA64_Pkr3:   return "pkr3";
        case CV_IA64_Pkr4:   return "pkr4";
        case CV_IA64_Pkr5:   return "pkr5";
        case CV_IA64_Pkr6:   return "pkr6";
        case CV_IA64_Pkr7:   return "pkr7";
        case CV_IA64_Pkr8:   return "pkr8";
        case CV_IA64_Pkr9:   return "pkr9";
        case CV_IA64_Pkr10:  return "pkr10";
        case CV_IA64_Pkr11:  return "pkr11";
        case CV_IA64_Pkr12:  return "pkr12";
        case CV_IA64_Pkr13:  return "pkr13";
        case CV_IA64_Pkr14:  return "pkr14";
        case CV_IA64_Pkr15:  return "pkr15";

        // Region Registers

        case CV_IA64_Rr0:    return "rr0";
        case CV_IA64_Rr1:    return "rr1";
        case CV_IA64_Rr2:    return "rr2";
        case CV_IA64_Rr3:    return "rr3";
        case CV_IA64_Rr4:    return "rr4";
        case CV_IA64_Rr5:    return "rr5";
        case CV_IA64_Rr6:    return "rr6";
        case CV_IA64_Rr7:    return "rr7";

        // Performance Monitor Data Registers

        case CV_IA64_PFD0:   return "pfd0";
        case CV_IA64_PFD1:   return "pfd1";
        case CV_IA64_PFD2:   return "pfd2";
        case CV_IA64_PFD3:   return "pfd3";
        case CV_IA64_PFD4:   return "pfd4";
        case CV_IA64_PFD5:   return "pfd5";
        case CV_IA64_PFD6:   return "pfd6";
        case CV_IA64_PFD7:   return "pfd7";
        case CV_IA64_PFD8:   return "pfd8";
        case CV_IA64_PFD9:   return "pfd9";
        case CV_IA64_PFD10:  return "pfd10";
        case CV_IA64_PFD11:  return "pfd11";
        case CV_IA64_PFD12:  return "pfd12";
        case CV_IA64_PFD13:  return "pfd13";
        case CV_IA64_PFD14:  return "pfd14";
        case CV_IA64_PFD15:  return "pfd15";
        case CV_IA64_PFD16:  return "pfd16";
        case CV_IA64_PFD17:  return "pfd17";

        // Performance Monitor Config Registers

        case CV_IA64_PFC0:   return "pfc0";
        case CV_IA64_PFC1:   return "pfc1";
        case CV_IA64_PFC2:   return "pfc2";
        case CV_IA64_PFC3:   return "pfc3";
        case CV_IA64_PFC4:   return "pfc4";
        case CV_IA64_PFC5:   return "pfc5";
        case CV_IA64_PFC6:   return "pfc6";
        case CV_IA64_PFC7:   return "pfc7";
        case CV_IA64_PFC8:   return "pfc8";
        case CV_IA64_PFC9:   return "pfc9";
        case CV_IA64_PFC10:  return "pfc10";
        case CV_IA64_PFC11:  return "pfc11";
        case CV_IA64_PFC12:  return "pfc12";
        case CV_IA64_PFC13:  return "pfc13";
        case CV_IA64_PFC14:  return "pfc14";
        case CV_IA64_PFC15:  return "pfc15";

        // Instruction Translation Registers

        case CV_IA64_TrI0:   return "tri0";
        case CV_IA64_TrI1:   return "tri1";
        case CV_IA64_TrI2:   return "tri2";
        case CV_IA64_TrI3:   return "tri3";
        case CV_IA64_TrI4:   return "tri4";
        case CV_IA64_TrI5:   return "tri5";
        case CV_IA64_TrI6:   return "tri6";
        case CV_IA64_TrI7:   return "tri7";

        // Data Translation Registers

        case CV_IA64_TrD0:   return "trd0";
        case CV_IA64_TrD1:   return "trd1";
        case CV_IA64_TrD2:   return "trd2";
        case CV_IA64_TrD3:   return "trd3";
        case CV_IA64_TrD4:   return "trd4";
        case CV_IA64_TrD5:   return "trd5";
        case CV_IA64_TrD6:   return "trd6";
        case CV_IA64_TrD7:   return "trd7";

        // Instruction Breakpoint Registers

        case CV_IA64_DbI0:   return "dbi0";
        case CV_IA64_DbI1:   return "dbi1";
        case CV_IA64_DbI2:   return "dbi2";
        case CV_IA64_DbI3:   return "dbi3";
        case CV_IA64_DbI4:   return "dbi4";
        case CV_IA64_DbI5:   return "dbi5";
        case CV_IA64_DbI6:   return "dbi6";
        case CV_IA64_DbI7:   return "dbi7";

        // Data Breakpoint Registers

        case CV_IA64_DbD0:   return "dbd0";
        case CV_IA64_DbD1:   return "dbd1";
        case CV_IA64_DbD2:   return "dbd2";
        case CV_IA64_DbD3:   return "dbd3";
        case CV_IA64_DbD4:   return "dbd4";
        case CV_IA64_DbD5:   return "dbd5";
        case CV_IA64_DbD6:   return "dbd6";
        case CV_IA64_DbD7:   return "dbd7";
      }
      break;


    case CV_CFL_TRICORE:
      //
      // Register set for the TriCore processor.
      //
      switch ( reg )
      {
        case CV_TRI_NOREG:   return "noreg";

        // General Purpose Data Registers

        case CV_TRI_D0:      return "d0";
        case CV_TRI_D1:      return "d1";
        case CV_TRI_D2:      return "d2";
        case CV_TRI_D3:      return "d3";
        case CV_TRI_D4:      return "d4";
        case CV_TRI_D5:      return "d5";
        case CV_TRI_D6:      return "d6";
        case CV_TRI_D7:      return "d7";
        case CV_TRI_D8:      return "d8";
        case CV_TRI_D9:      return "d9";
        case CV_TRI_D10:     return "d10";
        case CV_TRI_D11:     return "d11";
        case CV_TRI_D12:     return "d12";
        case CV_TRI_D13:     return "d13";
        case CV_TRI_D14:     return "d14";
        case CV_TRI_D15:     return "d15";

        // General Purpose Address Registers

        case CV_TRI_A0:      return "a0";
        case CV_TRI_A1:      return "a1";
        case CV_TRI_A2:      return "a2";
        case CV_TRI_A3:      return "a3";
        case CV_TRI_A4:      return "a4";
        case CV_TRI_A5:      return "a5";
        case CV_TRI_A6:      return "a6";
        case CV_TRI_A7:      return "a7";
        case CV_TRI_A8:      return "a8";
        case CV_TRI_A9:      return "a9";
        case CV_TRI_A10:     return "a10";
        case CV_TRI_A11:     return "a11";
        case CV_TRI_A12:     return "a12";
        case CV_TRI_A13:     return "a13";
        case CV_TRI_A14:     return "a14";
        case CV_TRI_A15:     return "a15";

        // Extended (64-bit) data registers

        case CV_TRI_E0:      return "e0";
        case CV_TRI_E2:      return "e2";
        case CV_TRI_E4:      return "e4";
        case CV_TRI_E6:      return "e6";
        case CV_TRI_E8:      return "e8";
        case CV_TRI_E10:     return "e10";
        case CV_TRI_E12:     return "e12";
        case CV_TRI_E14:     return "e14";

        // Extended (64-bit) address registers

        case CV_TRI_EA0:     return "ea0";
        case CV_TRI_EA2:     return "ea2";
        case CV_TRI_EA4:     return "ea4";
        case CV_TRI_EA6:     return "ea6";
        case CV_TRI_EA8:     return "ea8";
        case CV_TRI_EA10:    return "ea10";
        case CV_TRI_EA12:    return "ea12";
        case CV_TRI_EA14:    return "ea14";

        case CV_TRI_PSW:     return "psw";
        case CV_TRI_PCXI:    return "pcxi";
        case CV_TRI_PC:      return "pc";
        case CV_TRI_FCX:     return "fcx";
        case CV_TRI_LCX:     return "lcx";
        case CV_TRI_ISP:     return "isp";
        case CV_TRI_ICR:     return "icr";
        case CV_TRI_BIV:     return "biv";
        case CV_TRI_BTV:     return "btv";
        case CV_TRI_SYSCON:  return "syscon";
        case CV_TRI_DPRx_0:  return "dprx_0";
        case CV_TRI_DPRx_1:  return "dprx_1";
        case CV_TRI_DPRx_2:  return "dprx_2";
        case CV_TRI_DPRx_3:  return "dprx_3";
//        case CV_TRI_CPRx_0:  return "cprx_0";
//        case CV_TRI_CPRx_1:  return "cprx_1";
//        case CV_TRI_CPRx_2:  return "cprx_2";
//        case CV_TRI_CPRx_3:  return "cprx_3";
//        case CV_TRI_DPMx_0:  return "dpmx_0";
//        case CV_TRI_DPMx_1:  return "dpmx_1";
//        case CV_TRI_DPMx_2:  return "dpmx_2";
//        case CV_TRI_DPMx_3:  return "dpmx_3";
//        case CV_TRI_CPMx_0:  return "cpmx_0";
//        case CV_TRI_CPMx_1:  return "cpmx_1";
//        case CV_TRI_CPMx_2:  return "cpmx_2";
//        case CV_TRI_CPMx_3:  return "cpmx_3";
        case CV_TRI_DBGSSR:  return "dbgssr";
        case CV_TRI_EXEVT:   return "exevt";
        case CV_TRI_SWEVT:   return "swevt";
        case CV_TRI_CREVT:   return "crevt";
        case CV_TRI_TRnEVT:  return "trnevt";
        case CV_TRI_MMUCON:  return "mmucon";
        case CV_TRI_ASI:     return "asi";
        case CV_TRI_TVA:     return "tva";
        case CV_TRI_TPA:     return "tpa";
        case CV_TRI_TPX:     return "tpx";
        case CV_TRI_TFA:     return "tfa";
      }
      break;

    case CV_CFL_AM33:
      //
      // Register set for the AM33 and related processors.
      //
      switch ( reg )
      {
        case CV_AM33_NOREG:  return "noreg";

        // "Extended" (general purpose integer) registers
        case CV_AM33_E0:     return "e0";
        case CV_AM33_E1:     return "e1";
        case CV_AM33_E2:     return "e2";
        case CV_AM33_E3:     return "e3";
        case CV_AM33_E4:     return "e4";
        case CV_AM33_E5:     return "e5";
        case CV_AM33_E6:     return "e6";
        case CV_AM33_E7:     return "e7";

        // Address registers
        case CV_AM33_A0:     return "a0";
        case CV_AM33_A1:     return "a1";
        case CV_AM33_A2:     return "a2";
        case CV_AM33_A3:     return "a3";

        // Integer data registers
        case CV_AM33_D0:     return "d0";
        case CV_AM33_D1:     return "d1";
        case CV_AM33_D2:     return "d2";
        case CV_AM33_D3:     return "d3";

        // (Single-precision) floating-point registers
        case CV_AM33_FS0:    return "fs0";
        case CV_AM33_FS1:    return "fs1";
        case CV_AM33_FS2:    return "fs2";
        case CV_AM33_FS3:    return "fs3";
        case CV_AM33_FS4:    return "fs4";
        case CV_AM33_FS5:    return "fs5";
        case CV_AM33_FS6:    return "fs6";
        case CV_AM33_FS7:    return "fs7";
        case CV_AM33_FS8:    return "fs8";
        case CV_AM33_FS9:    return "fs9";
        case CV_AM33_FS10:   return "fs10";
        case CV_AM33_FS11:   return "fs11";
        case CV_AM33_FS12:   return "fs12";
        case CV_AM33_FS13:   return "fs13";
        case CV_AM33_FS14:   return "fs14";
        case CV_AM33_FS15:   return "fs15";
        case CV_AM33_FS16:   return "fs16";
        case CV_AM33_FS17:   return "fs17";
        case CV_AM33_FS18:   return "fs18";
        case CV_AM33_FS19:   return "fs19";
        case CV_AM33_FS20:   return "fs20";
        case CV_AM33_FS21:   return "fs21";
        case CV_AM33_FS22:   return "fs22";
        case CV_AM33_FS23:   return "fs23";
        case CV_AM33_FS24:   return "fs24";
        case CV_AM33_FS25:   return "fs25";
        case CV_AM33_FS26:   return "fs26";
        case CV_AM33_FS27:   return "fs27";
        case CV_AM33_FS28:   return "fs28";
        case CV_AM33_FS29:   return "fs29";
        case CV_AM33_FS30:   return "fs30";
        case CV_AM33_FS31:   return "fs31";

        // Special purpose registers

        // Stack pointer
        case CV_AM33_SP:     return "sp";

        // Program counter
        case CV_AM33_PC:     return "pc";

        // Multiply-divide/accumulate registers
        case CV_AM33_MDR:    return "mdr";
        case CV_AM33_MDRQ:   return "mdrq";
        case CV_AM33_MCRH:   return "mcrh";
        case CV_AM33_MCRL:   return "mcrl";
        case CV_AM33_MCVF:   return "mcvf";

        // CPU status words
        case CV_AM33_EPSW:   return "epsw";
        case CV_AM33_FPCR:   return "fpcr";

        // Loop buffer registers
        case CV_AM33_LIR:    return "lir";
        case CV_AM33_LAR:    return "lar";
      }
      break;

    case CV_CFL_M32R:
      //
      // Register set for the Mitsubishi M32R
      //
      switch ( reg )
      {
        case CV_M32R_NOREG:  return "noreg";
        case CV_M32R_R0:     return "r0";
        case CV_M32R_R1:     return "r1";
        case CV_M32R_R2:     return "r2";
        case CV_M32R_R3:     return "r3";
        case CV_M32R_R4:     return "r4";
        case CV_M32R_R5:     return "r5";
        case CV_M32R_R6:     return "r6";
        case CV_M32R_R7:     return "r7";
        case CV_M32R_R8:     return "r8";
        case CV_M32R_R9:     return "r9";
        case CV_M32R_R10:    return "r10";
        case CV_M32R_R11:    return "r11";
        case CV_M32R_R12:    return "r12";// Gloabal Pointer, if used
        case CV_M32R_R13:    return "r13";// Frame Pointer, if allocated
        case CV_M32R_R14:    return "r14";// Link Register
        case CV_M32R_R15:    return "r15";// Stack Pointer
        case CV_M32R_PSW:    return "psw";// Preocessor Status Register
        case CV_M32R_CBR:    return "cbr";// Condition Bit Register
        case CV_M32R_SPI:    return "spi";// Interrupt Stack Pointer
        case CV_M32R_SPU:    return "spu";// User Stack Pointer
        case CV_M32R_SPO:    return "spo";// OS Stack Pointer
        case CV_M32R_BPC:    return "bpc";// Backup Program Counter
        case CV_M32R_ACHI:   return "achi";// Accumulator High
        case CV_M32R_ACLO:   return "aclo";// Accumulator Low
        case CV_M32R_PC:     return "pc";// Program Counter
      }
      break;

      //
      // Register set for the SuperH SHMedia processor including compact
      // mode
      //
    case CV_CFL_SHMEDIA:
      switch ( reg )
      {
        // Integer - 64 bit general registers
        case CV_SHMEDIA_NOREG:return "noreg";
        case CV_SHMEDIA_R0:  return "r0";
        case CV_SHMEDIA_R1:  return "r1";
        case CV_SHMEDIA_R2:  return "r2";
        case CV_SHMEDIA_R3:  return "r3";
        case CV_SHMEDIA_R4:  return "r4";
        case CV_SHMEDIA_R5:  return "r5";
        case CV_SHMEDIA_R6:  return "r6";
        case CV_SHMEDIA_R7:  return "r7";
        case CV_SHMEDIA_R8:  return "r8";
        case CV_SHMEDIA_R9:  return "r9";
        case CV_SHMEDIA_R10: return "r10";
        case CV_SHMEDIA_R11: return "r11";
        case CV_SHMEDIA_R12: return "r12";
        case CV_SHMEDIA_R13: return "r13";
        case CV_SHMEDIA_R14: return "r14";
        case CV_SHMEDIA_R15: return "r15";
        case CV_SHMEDIA_R16: return "r16";
        case CV_SHMEDIA_R17: return "r17";
        case CV_SHMEDIA_R18: return "r18";
        case CV_SHMEDIA_R19: return "r19";
        case CV_SHMEDIA_R20: return "r20";
        case CV_SHMEDIA_R21: return "r21";
        case CV_SHMEDIA_R22: return "r22";
        case CV_SHMEDIA_R23: return "r23";
        case CV_SHMEDIA_R24: return "r24";
        case CV_SHMEDIA_R25: return "r25";
        case CV_SHMEDIA_R26: return "r26";
        case CV_SHMEDIA_R27: return "r27";
        case CV_SHMEDIA_R28: return "r28";
        case CV_SHMEDIA_R29: return "r29";
        case CV_SHMEDIA_R30: return "r30";
        case CV_SHMEDIA_R31: return "r31";
        case CV_SHMEDIA_R32: return "r32";
        case CV_SHMEDIA_R33: return "r33";
        case CV_SHMEDIA_R34: return "r34";
        case CV_SHMEDIA_R35: return "r35";
        case CV_SHMEDIA_R36: return "r36";
        case CV_SHMEDIA_R37: return "r37";
        case CV_SHMEDIA_R38: return "r38";
        case CV_SHMEDIA_R39: return "r39";
        case CV_SHMEDIA_R40: return "r40";
        case CV_SHMEDIA_R41: return "r41";
        case CV_SHMEDIA_R42: return "r42";
        case CV_SHMEDIA_R43: return "r43";
        case CV_SHMEDIA_R44: return "r44";
        case CV_SHMEDIA_R45: return "r45";
        case CV_SHMEDIA_R46: return "r46";
        case CV_SHMEDIA_R47: return "r47";
        case CV_SHMEDIA_R48: return "r48";
        case CV_SHMEDIA_R49: return "r49";
        case CV_SHMEDIA_R50: return "r50";
        case CV_SHMEDIA_R51: return "r51";
        case CV_SHMEDIA_R52: return "r52";
        case CV_SHMEDIA_R53: return "r53";
        case CV_SHMEDIA_R54: return "r54";
        case CV_SHMEDIA_R55: return "r55";
        case CV_SHMEDIA_R56: return "r56";
        case CV_SHMEDIA_R57: return "r57";
        case CV_SHMEDIA_R58: return "r58";
        case CV_SHMEDIA_R59: return "r59";
        case CV_SHMEDIA_R60: return "r60";
        case CV_SHMEDIA_R61: return "r61";
        case CV_SHMEDIA_R62: return "r62";
        case CV_SHMEDIA_R63: return "r63";

        // Target Registers - 32 bit
        case CV_SHMEDIA_TR0: return "tr0";
        case CV_SHMEDIA_TR1: return "tr1";
        case CV_SHMEDIA_TR2: return "tr2";
        case CV_SHMEDIA_TR3: return "tr3";
        case CV_SHMEDIA_TR4: return "tr4";
        case CV_SHMEDIA_TR5: return "tr5";
        case CV_SHMEDIA_TR6: return "tr6";
        case CV_SHMEDIA_TR7: return "tr7";
        case CV_SHMEDIA_TR8: return "tr8";  // future-proof
        case CV_SHMEDIA_TR9: return "tr9";  // future-proof
        case CV_SHMEDIA_TR10:return "tr10"; // future-proof
        case CV_SHMEDIA_TR11:return "tr11"; // future-proof
        case CV_SHMEDIA_TR12:return "tr12"; // future-proof
        case CV_SHMEDIA_TR13:return "tr13"; // future-proof
        case CV_SHMEDIA_TR14:return "tr14"; // future-proof
        case CV_SHMEDIA_TR15:return "tr15"; // future-proof

        // Single - 32 bit fp registers
        case CV_SHMEDIA_FR0: return "fr0";
        case CV_SHMEDIA_FR1: return "fr1";
        case CV_SHMEDIA_FR2: return "fr2";
        case CV_SHMEDIA_FR3: return "fr3";
        case CV_SHMEDIA_FR4: return "fr4";
        case CV_SHMEDIA_FR5: return "fr5";
        case CV_SHMEDIA_FR6: return "fr6";
        case CV_SHMEDIA_FR7: return "fr7";
        case CV_SHMEDIA_FR8: return "fr8";
        case CV_SHMEDIA_FR9: return "fr9";
        case CV_SHMEDIA_FR10:return "fr10";
        case CV_SHMEDIA_FR11:return "fr11";
        case CV_SHMEDIA_FR12:return "fr12";
        case CV_SHMEDIA_FR13:return "fr13";
        case CV_SHMEDIA_FR14:return "fr14";
        case CV_SHMEDIA_FR15:return "fr15";
        case CV_SHMEDIA_FR16:return "fr16";
        case CV_SHMEDIA_FR17:return "fr17";
        case CV_SHMEDIA_FR18:return "fr18";
        case CV_SHMEDIA_FR19:return "fr19";
        case CV_SHMEDIA_FR20:return "fr20";
        case CV_SHMEDIA_FR21:return "fr21";
        case CV_SHMEDIA_FR22:return "fr22";
        case CV_SHMEDIA_FR23:return "fr23";
        case CV_SHMEDIA_FR24:return "fr24";
        case CV_SHMEDIA_FR25:return "fr25";
        case CV_SHMEDIA_FR26:return "fr26";
        case CV_SHMEDIA_FR27:return "fr27";
        case CV_SHMEDIA_FR28:return "fr28";
        case CV_SHMEDIA_FR29:return "fr29";
        case CV_SHMEDIA_FR30:return "fr30";
        case CV_SHMEDIA_FR31:return "fr31";
        case CV_SHMEDIA_FR32:return "fr32";
        case CV_SHMEDIA_FR33:return "fr33";
        case CV_SHMEDIA_FR34:return "fr34";
        case CV_SHMEDIA_FR35:return "fr35";
        case CV_SHMEDIA_FR36:return "fr36";
        case CV_SHMEDIA_FR37:return "fr37";
        case CV_SHMEDIA_FR38:return "fr38";
        case CV_SHMEDIA_FR39:return "fr39";
        case CV_SHMEDIA_FR40:return "fr40";
        case CV_SHMEDIA_FR41:return "fr41";
        case CV_SHMEDIA_FR42:return "fr42";
        case CV_SHMEDIA_FR43:return "fr43";
        case CV_SHMEDIA_FR44:return "fr44";
        case CV_SHMEDIA_FR45:return "fr45";
        case CV_SHMEDIA_FR46:return "fr46";
        case CV_SHMEDIA_FR47:return "fr47";
        case CV_SHMEDIA_FR48:return "fr48";
        case CV_SHMEDIA_FR49:return "fr49";
        case CV_SHMEDIA_FR50:return "fr50";
        case CV_SHMEDIA_FR51:return "fr51";
        case CV_SHMEDIA_FR52:return "fr52";
        case CV_SHMEDIA_FR53:return "fr53";
        case CV_SHMEDIA_FR54:return "fr54";
        case CV_SHMEDIA_FR55:return "fr55";
        case CV_SHMEDIA_FR56:return "fr56";
        case CV_SHMEDIA_FR57:return "fr57";
        case CV_SHMEDIA_FR58:return "fr58";
        case CV_SHMEDIA_FR59:return "fr59";
        case CV_SHMEDIA_FR60:return "fr60";
        case CV_SHMEDIA_FR61:return "fr61";
        case CV_SHMEDIA_FR62:return "fr62";
        case CV_SHMEDIA_FR63:return "fr63";

        // Double - 64 bit synonyms for 32bit fp register pairs
        //          subtract 128 to find first base single register
        case CV_SHMEDIA_DR0: return "dr0";
        case CV_SHMEDIA_DR2: return "dr2";
        case CV_SHMEDIA_DR4: return "dr4";
        case CV_SHMEDIA_DR6: return "dr6";
        case CV_SHMEDIA_DR8: return "dr8";
        case CV_SHMEDIA_DR10:return "dr10";
        case CV_SHMEDIA_DR12:return "dr12";
        case CV_SHMEDIA_DR14:return "dr14";
        case CV_SHMEDIA_DR16:return "dr16";
        case CV_SHMEDIA_DR18:return "dr18";
        case CV_SHMEDIA_DR20:return "dr20";
        case CV_SHMEDIA_DR22:return "dr22";
        case CV_SHMEDIA_DR24:return "dr24";
        case CV_SHMEDIA_DR26:return "dr26";
        case CV_SHMEDIA_DR28:return "dr28";
        case CV_SHMEDIA_DR30:return "dr30";
        case CV_SHMEDIA_DR32:return "dr32";
        case CV_SHMEDIA_DR34:return "dr34";
        case CV_SHMEDIA_DR36:return "dr36";
        case CV_SHMEDIA_DR38:return "dr38";
        case CV_SHMEDIA_DR40:return "dr40";
        case CV_SHMEDIA_DR42:return "dr42";
        case CV_SHMEDIA_DR44:return "dr44";
        case CV_SHMEDIA_DR46:return "dr46";
        case CV_SHMEDIA_DR48:return "dr48";
        case CV_SHMEDIA_DR50:return "dr50";
        case CV_SHMEDIA_DR52:return "dr52";
        case CV_SHMEDIA_DR54:return "dr54";
        case CV_SHMEDIA_DR56:return "dr56";
        case CV_SHMEDIA_DR58:return "dr58";
        case CV_SHMEDIA_DR60:return "dr60";
        case CV_SHMEDIA_DR62:return "dr62";

        // Vector - 128 bit synonyms for 32bit fp register quads
        //          subtract 384 to find first base single register
        case CV_SHMEDIA_FV0: return "fv0";
        case CV_SHMEDIA_FV4: return "fv4";
        case CV_SHMEDIA_FV8: return "fv8";
        case CV_SHMEDIA_FV12:return "fv12";
        case CV_SHMEDIA_FV16:return "fv16";
        case CV_SHMEDIA_FV20:return "fv20";
        case CV_SHMEDIA_FV24:return "fv24";
        case CV_SHMEDIA_FV28:return "fv28";
        case CV_SHMEDIA_FV32:return "fv32";
        case CV_SHMEDIA_FV36:return "fv36";
        case CV_SHMEDIA_FV40:return "fv40";
        case CV_SHMEDIA_FV44:return "fv44";
        case CV_SHMEDIA_FV48:return "fv48";
        case CV_SHMEDIA_FV52:return "fv52";
        case CV_SHMEDIA_FV56:return "fv56";
        case CV_SHMEDIA_FV60:return "fv60";

        // Matrix - 512 bit synonyms for 16 adjacent 32bit fp registers
        //          subtract 896 to find first base single register
        case CV_SHMEDIA_MTRX0: return "mtrx0";
        case CV_SHMEDIA_MTRX16:return "mtrx16";
        case CV_SHMEDIA_MTRX32:return "mtrx32";
        case CV_SHMEDIA_MTRX48:return "mtrx48";

        // Control - Implementation defined 64bit control registers
        case CV_SHMEDIA_CR0: return "cr0";
        case CV_SHMEDIA_CR1: return "cr1";
        case CV_SHMEDIA_CR2: return "cr2";
        case CV_SHMEDIA_CR3: return "cr3";
        case CV_SHMEDIA_CR4: return "cr4";
        case CV_SHMEDIA_CR5: return "cr5";
        case CV_SHMEDIA_CR6: return "cr6";
        case CV_SHMEDIA_CR7: return "cr7";
        case CV_SHMEDIA_CR8: return "cr8";
        case CV_SHMEDIA_CR9: return "cr9";
        case CV_SHMEDIA_CR10:return "cr10";
        case CV_SHMEDIA_CR11:return "cr11";
        case CV_SHMEDIA_CR12:return "cr12";
        case CV_SHMEDIA_CR13:return "cr13";
        case CV_SHMEDIA_CR14:return "cr14";
        case CV_SHMEDIA_CR15:return "cr15";
        case CV_SHMEDIA_CR16:return "cr16";
        case CV_SHMEDIA_CR17:return "cr17";
        case CV_SHMEDIA_CR18:return "cr18";
        case CV_SHMEDIA_CR19:return "cr19";
        case CV_SHMEDIA_CR20:return "cr20";
        case CV_SHMEDIA_CR21:return "cr21";
        case CV_SHMEDIA_CR22:return "cr22";
        case CV_SHMEDIA_CR23:return "cr23";
        case CV_SHMEDIA_CR24:return "cr24";
        case CV_SHMEDIA_CR25:return "cr25";
        case CV_SHMEDIA_CR26:return "cr26";
        case CV_SHMEDIA_CR27:return "cr27";
        case CV_SHMEDIA_CR28:return "cr28";
        case CV_SHMEDIA_CR29:return "cr29";
        case CV_SHMEDIA_CR30:return "cr30";
        case CV_SHMEDIA_CR31:return "cr31";
        case CV_SHMEDIA_CR32:return "cr32";
        case CV_SHMEDIA_CR33:return "cr33";
        case CV_SHMEDIA_CR34:return "cr34";
        case CV_SHMEDIA_CR35:return "cr35";
        case CV_SHMEDIA_CR36:return "cr36";
        case CV_SHMEDIA_CR37:return "cr37";
        case CV_SHMEDIA_CR38:return "cr38";
        case CV_SHMEDIA_CR39:return "cr39";
        case CV_SHMEDIA_CR40:return "cr40";
        case CV_SHMEDIA_CR41:return "cr41";
        case CV_SHMEDIA_CR42:return "cr42";
        case CV_SHMEDIA_CR43:return "cr43";
        case CV_SHMEDIA_CR44:return "cr44";
        case CV_SHMEDIA_CR45:return "cr45";
        case CV_SHMEDIA_CR46:return "cr46";
        case CV_SHMEDIA_CR47:return "cr47";
        case CV_SHMEDIA_CR48:return "cr48";
        case CV_SHMEDIA_CR49:return "cr49";
        case CV_SHMEDIA_CR50:return "cr50";
        case CV_SHMEDIA_CR51:return "cr51";
        case CV_SHMEDIA_CR52:return "cr52";
        case CV_SHMEDIA_CR53:return "cr53";
        case CV_SHMEDIA_CR54:return "cr54";
        case CV_SHMEDIA_CR55:return "cr55";
        case CV_SHMEDIA_CR56:return "cr56";
        case CV_SHMEDIA_CR57:return "cr57";
        case CV_SHMEDIA_CR58:return "cr58";
        case CV_SHMEDIA_CR59:return "cr59";
        case CV_SHMEDIA_CR60:return "cr60";
        case CV_SHMEDIA_CR61:return "cr61";
        case CV_SHMEDIA_CR62:return "cr62";
        case CV_SHMEDIA_CR63:return "cr63";

        case CV_SHMEDIA_FPSCR: return "fpscr";

        // Compact mode synonyms
//        case CV_SHMEDIA_GBR:  return "gbr";
        case CV_SHMEDIA_MACL: return "macl";// synonym for lower 32bits of media R17
        case CV_SHMEDIA_MACH: return "mach";// synonym for upper 32bits of media R17
//        case CV_SHMEDIA_PR:   return "pr";
        case CV_SHMEDIA_T:    return "t";// synonym for lowest bit of media R19
//        case CV_SHMEDIA_FPUL: return "fpul";
        case CV_SHMEDIA_PC:   return "pc";
//        case CV_SHMEDIA_SR:   return "sr";
      }
      break;

    case CV_CFL_AMD64:
      //
      // AMD64 registers
      //
      switch ( reg )
      {
        case CV_AMD64_AL:     return "al";
        case CV_AMD64_CL:     return "cl";
        case CV_AMD64_DL:     return "dl";
        case CV_AMD64_BL:     return "bl";
        case CV_AMD64_AH:     return "ah";
        case CV_AMD64_CH:     return "ch";
        case CV_AMD64_DH:     return "dh";
        case CV_AMD64_BH:     return "bh";
        case CV_AMD64_AX:     return "ax";
        case CV_AMD64_CX:     return "cx";
        case CV_AMD64_DX:     return "dx";
        case CV_AMD64_BX:     return "bx";
        case CV_AMD64_SP:     return "sp";
        case CV_AMD64_BP:     return "bp";
        case CV_AMD64_SI:     return "si";
        case CV_AMD64_DI:     return "di";
        case CV_AMD64_EAX:    return "eax";
        case CV_AMD64_ECX:    return "ecx";
        case CV_AMD64_EDX:    return "edx";
        case CV_AMD64_EBX:    return "ebx";
        case CV_AMD64_ESP:    return "esp";
        case CV_AMD64_EBP:    return "ebp";
        case CV_AMD64_ESI:    return "esi";
        case CV_AMD64_EDI:    return "edi";
        case CV_AMD64_ES:     return "es";
        case CV_AMD64_CS:     return "cs";
        case CV_AMD64_SS:     return "ss";
        case CV_AMD64_DS:     return "ds";
        case CV_AMD64_FS:     return "fs";
        case CV_AMD64_GS:     return "gs";
        case CV_AMD64_FLAGS:  return "flags";
        case CV_AMD64_RIP:    return "rip";
        case CV_AMD64_EFLAGS: return "eflags";

        // Control registers
        case CV_AMD64_CR0:    return "cr0";
        case CV_AMD64_CR1:    return "cr1";
        case CV_AMD64_CR2:    return "cr2";
        case CV_AMD64_CR3:    return "cr3";
        case CV_AMD64_CR4:    return "cr4";
        case CV_AMD64_CR8:    return "cr8";

        // Debug registers
        case CV_AMD64_DR0:    return "dr0";
        case CV_AMD64_DR1:    return "dr1";
        case CV_AMD64_DR2:    return "dr2";
        case CV_AMD64_DR3:    return "dr3";
        case CV_AMD64_DR4:    return "dr4";
        case CV_AMD64_DR5:    return "dr5";
        case CV_AMD64_DR6:    return "dr6";
        case CV_AMD64_DR7:    return "dr7";
        case CV_AMD64_DR8:    return "dr8";
        case CV_AMD64_DR9:    return "dr9";
        case CV_AMD64_DR10:   return "dr10";
        case CV_AMD64_DR11:   return "dr11";
        case CV_AMD64_DR12:   return "dr12";
        case CV_AMD64_DR13:   return "dr13";
        case CV_AMD64_DR14:   return "dr14";
        case CV_AMD64_DR15:   return "dr15";

        case CV_AMD64_GDTR:   return "gdtr";
        case CV_AMD64_GDTL:   return "gdtl";
        case CV_AMD64_IDTR:   return "idtr";
        case CV_AMD64_IDTL:   return "idtl";
        case CV_AMD64_LDTR:   return "ldtr";
        case CV_AMD64_TR:     return "tr";

        case CV_AMD64_ST0:    return "st0";
        case CV_AMD64_ST1:    return "st1";
        case CV_AMD64_ST2:    return "st2";
        case CV_AMD64_ST3:    return "st3";
        case CV_AMD64_ST4:    return "st4";
        case CV_AMD64_ST5:    return "st5";
        case CV_AMD64_ST6:    return "st6";
        case CV_AMD64_ST7:    return "st7";
        case CV_AMD64_CTRL:   return "ctrl";
        case CV_AMD64_STAT:   return "stat";
        case CV_AMD64_TAG:    return "tag";
        case CV_AMD64_FPIP:   return "fpip";
        case CV_AMD64_FPCS:   return "fpcs";
        case CV_AMD64_FPDO:   return "fpdo";
        case CV_AMD64_FPDS:   return "fpds";
        case CV_AMD64_ISEM:   return "isem";
        case CV_AMD64_FPEIP:  return "fpeip";
        case CV_AMD64_FPEDO:  return "fpedo";

        case CV_AMD64_MM0:    return "mm0";
        case CV_AMD64_MM1:    return "mm1";
        case CV_AMD64_MM2:    return "mm2";
        case CV_AMD64_MM3:    return "mm3";
        case CV_AMD64_MM4:    return "mm4";
        case CV_AMD64_MM5:    return "mm5";
        case CV_AMD64_MM6:    return "mm6";
        case CV_AMD64_MM7:    return "mm7";

        case CV_AMD64_XMM0:   return "xmm0";// KATMAI registers
        case CV_AMD64_XMM1:   return "xmm1";
        case CV_AMD64_XMM2:   return "xmm2";
        case CV_AMD64_XMM3:   return "xmm3";
        case CV_AMD64_XMM4:   return "xmm4";
        case CV_AMD64_XMM5:   return "xmm5";
        case CV_AMD64_XMM6:   return "xmm6";
        case CV_AMD64_XMM7:   return "xmm7";

        case CV_AMD64_XMM0_0: return "xmm0_0";  // KATMAI sub-registers
        case CV_AMD64_XMM0_1: return "xmm0_1";
        case CV_AMD64_XMM0_2: return "xmm0_2";
        case CV_AMD64_XMM0_3: return "xmm0_3";
        case CV_AMD64_XMM1_0: return "xmm1_0";
        case CV_AMD64_XMM1_1: return "xmm1_1";
        case CV_AMD64_XMM1_2: return "xmm1_2";
        case CV_AMD64_XMM1_3: return "xmm1_3";
        case CV_AMD64_XMM2_0: return "xmm2_0";
        case CV_AMD64_XMM2_1: return "xmm2_1";
        case CV_AMD64_XMM2_2: return "xmm2_2";
        case CV_AMD64_XMM2_3: return "xmm2_3";
        case CV_AMD64_XMM3_0: return "xmm3_0";
        case CV_AMD64_XMM3_1: return "xmm3_1";
        case CV_AMD64_XMM3_2: return "xmm3_2";
        case CV_AMD64_XMM3_3: return "xmm3_3";
        case CV_AMD64_XMM4_0: return "xmm4_0";
        case CV_AMD64_XMM4_1: return "xmm4_1";
        case CV_AMD64_XMM4_2: return "xmm4_2";
        case CV_AMD64_XMM4_3: return "xmm4_3";
        case CV_AMD64_XMM5_0: return "xmm5_0";
        case CV_AMD64_XMM5_1: return "xmm5_1";
        case CV_AMD64_XMM5_2: return "xmm5_2";
        case CV_AMD64_XMM5_3: return "xmm5_3";
        case CV_AMD64_XMM6_0: return "xmm6_0";
        case CV_AMD64_XMM6_1: return "xmm6_1";
        case CV_AMD64_XMM6_2: return "xmm6_2";
        case CV_AMD64_XMM6_3: return "xmm6_3";
        case CV_AMD64_XMM7_0: return "xmm7_0";
        case CV_AMD64_XMM7_1: return "xmm7_1";
        case CV_AMD64_XMM7_2: return "xmm7_2";
        case CV_AMD64_XMM7_3: return "xmm7_3";

        case CV_AMD64_XMM0L:  return "xmm0l";
        case CV_AMD64_XMM1L:  return "xmm1l";
        case CV_AMD64_XMM2L:  return "xmm2l";
        case CV_AMD64_XMM3L:  return "xmm3l";
        case CV_AMD64_XMM4L:  return "xmm4l";
        case CV_AMD64_XMM5L:  return "xmm5l";
        case CV_AMD64_XMM6L:  return "xmm6l";
        case CV_AMD64_XMM7L:  return "xmm7l";

        case CV_AMD64_XMM0H:  return "xmm0h";
        case CV_AMD64_XMM1H:  return "xmm1h";
        case CV_AMD64_XMM2H:  return "xmm2h";
        case CV_AMD64_XMM3H:  return "xmm3h";
        case CV_AMD64_XMM4H:  return "xmm4h";
        case CV_AMD64_XMM5H:  return "xmm5h";
        case CV_AMD64_XMM6H:  return "xmm6h";
        case CV_AMD64_XMM7H:  return "xmm7h";

        case CV_AMD64_MXCSR:  return "mxcsr"; // XMM status register

        case CV_AMD64_EMM0L:  return "emm0l"; // XMM sub-registers (WNI integer)
        case CV_AMD64_EMM1L:  return "emm1l";
        case CV_AMD64_EMM2L:  return "emm2l";
        case CV_AMD64_EMM3L:  return "emm3l";
        case CV_AMD64_EMM4L:  return "emm4l";
        case CV_AMD64_EMM5L:  return "emm5l";
        case CV_AMD64_EMM6L:  return "emm6l";
        case CV_AMD64_EMM7L:  return "emm7l";

        case CV_AMD64_EMM0H:  return "emm0h";
        case CV_AMD64_EMM1H:  return "emm1h";
        case CV_AMD64_EMM2H:  return "emm2h";
        case CV_AMD64_EMM3H:  return "emm3h";
        case CV_AMD64_EMM4H:  return "emm4h";
        case CV_AMD64_EMM5H:  return "emm5h";
        case CV_AMD64_EMM6H:  return "emm6h";
        case CV_AMD64_EMM7H:  return "emm7h";

        // do not change the order of these regs, first one must be even too
        case CV_AMD64_MM00:   return "mm00";
        case CV_AMD64_MM01:   return "mm01";
        case CV_AMD64_MM10:   return "mm10";
        case CV_AMD64_MM11:   return "mm11";
        case CV_AMD64_MM20:   return "mm20";
        case CV_AMD64_MM21:   return "mm21";
        case CV_AMD64_MM30:   return "mm30";
        case CV_AMD64_MM31:   return "mm31";
        case CV_AMD64_MM40:   return "mm40";
        case CV_AMD64_MM41:   return "mm41";
        case CV_AMD64_MM50:   return "mm50";
        case CV_AMD64_MM51:   return "mm51";
        case CV_AMD64_MM60:   return "mm60";
        case CV_AMD64_MM61:   return "mm61";
        case CV_AMD64_MM70:   return "mm70";
        case CV_AMD64_MM71:   return "mm71";

        // Extended KATMAI registers
        case CV_AMD64_XMM8:   return "xmm8";// KATMAI registers
        case CV_AMD64_XMM9:   return "xmm9";
        case CV_AMD64_XMM10:  return "xmm10";
        case CV_AMD64_XMM11:  return "xmm11";
        case CV_AMD64_XMM12:  return "xmm12";
        case CV_AMD64_XMM13:  return "xmm13";
        case CV_AMD64_XMM14:  return "xmm14";
        case CV_AMD64_XMM15:  return "xmm15";

        case CV_AMD64_XMM8_0: return "xmm8_0";  // KATMAI sub-registers
        case CV_AMD64_XMM8_1: return "xmm8_1";
        case CV_AMD64_XMM8_2: return "xmm8_2";
        case CV_AMD64_XMM8_3: return "xmm8_3";
        case CV_AMD64_XMM9_0: return "xmm9_0";
        case CV_AMD64_XMM9_1: return "xmm9_1";
        case CV_AMD64_XMM9_2: return "xmm9_2";
        case CV_AMD64_XMM9_3: return "xmm9_3";
        case CV_AMD64_XMM10_0:return "xmm10_0";
        case CV_AMD64_XMM10_1:return "xmm10_1";
        case CV_AMD64_XMM10_2:return "xmm10_2";
        case CV_AMD64_XMM10_3:return "xmm10_3";
        case CV_AMD64_XMM11_0:return "xmm11_0";
        case CV_AMD64_XMM11_1:return "xmm11_1";
        case CV_AMD64_XMM11_2:return "xmm11_2";
        case CV_AMD64_XMM11_3:return "xmm11_3";
        case CV_AMD64_XMM12_0:return "xmm12_0";
        case CV_AMD64_XMM12_1:return "xmm12_1";
        case CV_AMD64_XMM12_2:return "xmm12_2";
        case CV_AMD64_XMM12_3:return "xmm12_3";
        case CV_AMD64_XMM13_0:return "xmm13_0";
        case CV_AMD64_XMM13_1:return "xmm13_1";
        case CV_AMD64_XMM13_2:return "xmm13_2";
        case CV_AMD64_XMM13_3:return "xmm13_3";
        case CV_AMD64_XMM14_0:return "xmm14_0";
        case CV_AMD64_XMM14_1:return "xmm14_1";
        case CV_AMD64_XMM14_2:return "xmm14_2";
        case CV_AMD64_XMM14_3:return "xmm14_3";
        case CV_AMD64_XMM15_0:return "xmm15_0";
        case CV_AMD64_XMM15_1:return "xmm15_1";
        case CV_AMD64_XMM15_2:return "xmm15_2";
        case CV_AMD64_XMM15_3:return "xmm15_3";

        case CV_AMD64_XMM8L:  return "xmm8l";
        case CV_AMD64_XMM9L:  return "xmm9l";
        case CV_AMD64_XMM10L: return "xmm10l";
        case CV_AMD64_XMM11L: return "xmm11l";
        case CV_AMD64_XMM12L: return "xmm12l";
        case CV_AMD64_XMM13L: return "xmm13l";
        case CV_AMD64_XMM14L: return "xmm14l";
        case CV_AMD64_XMM15L: return "xmm15l";

        case CV_AMD64_XMM8H:  return "xmm8h";
        case CV_AMD64_XMM9H:  return "xmm9h";
        case CV_AMD64_XMM10H: return "xmm10h";
        case CV_AMD64_XMM11H: return "xmm11h";
        case CV_AMD64_XMM12H: return "xmm12h";
        case CV_AMD64_XMM13H: return "xmm13h";
        case CV_AMD64_XMM14H: return "xmm14h";
        case CV_AMD64_XMM15H: return "xmm15h";

        case CV_AMD64_EMM8L:  return "emm8l"; // XMM sub-registers (WNI integer)
        case CV_AMD64_EMM9L:  return "emm9l";
        case CV_AMD64_EMM10L: return "emm10l";
        case CV_AMD64_EMM11L: return "emm11l";
        case CV_AMD64_EMM12L: return "emm12l";
        case CV_AMD64_EMM13L: return "emm13l";
        case CV_AMD64_EMM14L: return "emm14l";
        case CV_AMD64_EMM15L: return "emm15l";

        case CV_AMD64_EMM8H:  return "emm8h";
        case CV_AMD64_EMM9H:  return "emm9h";
        case CV_AMD64_EMM10H: return "emm10h";
        case CV_AMD64_EMM11H: return "emm11h";
        case CV_AMD64_EMM12H: return "emm12h";
        case CV_AMD64_EMM13H: return "emm13h";
        case CV_AMD64_EMM14H: return "emm14h";
        case CV_AMD64_EMM15H: return "emm15h";

        // Low byte forms of some standard registers
        case CV_AMD64_SIL:    return "sil";
        case CV_AMD64_DIL:    return "dil";
        case CV_AMD64_BPL:    return "bpl";
        case CV_AMD64_SPL:    return "spl";

        // 64-bit regular registers
        case CV_AMD64_RAX:    return "rax";
        case CV_AMD64_RBX:    return "rbx";
        case CV_AMD64_RCX:    return "rcx";
        case CV_AMD64_RDX:    return "rdx";
        case CV_AMD64_RSI:    return "rsi";
        case CV_AMD64_RDI:    return "rdi";
        case CV_AMD64_RBP:    return "rbp";
        case CV_AMD64_RSP:    return "rsp";

        // 64-bit integer registers with 8-, 16-, and 32-bit forms (B, W, and D)
        case CV_AMD64_R8:     return "r8";
        case CV_AMD64_R9:     return "r9";
        case CV_AMD64_R10:    return "r10";
        case CV_AMD64_R11:    return "r11";
        case CV_AMD64_R12:    return "r12";
        case CV_AMD64_R13:    return "r13";
        case CV_AMD64_R14:    return "r14";
        case CV_AMD64_R15:    return "r15";

        case CV_AMD64_R8B:    return "r8b";
        case CV_AMD64_R9B:    return "r9b";
        case CV_AMD64_R10B:   return "r10b";
        case CV_AMD64_R11B:   return "r11b";
        case CV_AMD64_R12B:   return "r12b";
        case CV_AMD64_R13B:   return "r13b";
        case CV_AMD64_R14B:   return "r14b";
        case CV_AMD64_R15B:   return "r15b";

        case CV_AMD64_R8W:    return "r8w";
        case CV_AMD64_R9W:    return "r9w";
        case CV_AMD64_R10W:   return "r10w";
        case CV_AMD64_R11W:   return "r11w";
        case CV_AMD64_R12W:   return "r12w";
        case CV_AMD64_R13W:   return "r13w";
        case CV_AMD64_R14W:   return "r14w";
        case CV_AMD64_R15W:   return "r15w";

        case CV_AMD64_R8D:    return "r8d";
        case CV_AMD64_R9D:    return "r9d";
        case CV_AMD64_R10D:   return "r10d";
        case CV_AMD64_R11D:   return "r11d";
        case CV_AMD64_R12D:   return "r12d";
        case CV_AMD64_R13D:   return "r13d";
        case CV_AMD64_R14D:   return "r14d";
        case CV_AMD64_R15D:   return "r15d";
      }

    default:
      break;
  }
  static char buf[MAXSTR];
  qsnprintf(buf, sizeof(buf), "reg %d", reg);
  return buf;
}

#endif
