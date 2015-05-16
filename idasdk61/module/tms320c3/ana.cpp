/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *      Texas Instruments's TMS5320C3X
 *
 */

#include "tms320c3x.hpp"
#include <srarea.hpp>

#define FUNCS_COUNT 3

struct funcdesc_t
{
  bool (*func)(int);
  int mask;
  int shift;
};

struct opcode
{
  uint16 itype;
  unsigned int cmdidx;
  struct funcdesc_t funcs[FUNCS_COUNT];
  uchar itype2;
  struct funcdesc_t funcs2[FUNCS_COUNT];
  bool ispar;
};

static op_t *op;       // current operand

//----------------------------------------------------------------------
inline void opreg(uint16 reg)
{
  op->type = o_reg;
  op->dtyp = dt_byte;
  op->reg  = reg;
}

//----------------------------------------------------------------------
static void make_o_mem(void)
{

  switch ( cmd.itype )
  {
    case TMS320C3X_BR:
    case TMS320C3X_BRD:
    case TMS320C3X_CALL:
    case TMS320C3X_RPTB:
    case TMS320C3X_Bcond:
    case TMS320C3X_DBcond:
    case TMS320C3X_CALLcond:
          op->type   = o_near;
          op->dtyp   = dt_code;
          return;
  }

  op->type   = o_mem;
  op->dtyp   = dt_byte;
}

//----------------------------------------------------------------------
static bool D_adr24(int value)
{
        op->addr = value & 0xffffff;
        make_o_mem();
        return true;
}
//----------------------------------------------------------------------
static bool D_PC_Displ(int value)
{
        int16 disp = value & 0xffff;

        if ( value & 0x200000 )
     D_adr24( int(cmd.ea + disp + 3) );    // delayed branch
        else
     D_adr24( int(cmd.ea + disp + 1) );

        return true;
}

//----------------------------------------------------------------------
static bool imm8(int value)
{
        op->type  = o_imm;
        op->dtyp  = dt_byte;
        op->value = value & 0xff;
        return true;
}

//----------------------------------------------------------------------
static bool D_regs(int value)   // Интерпретация номеров регистров
{

 if ( (value & 0x1f) > 0x1b)
        return false;
 else
 {
         if ( (value & 0x1f) == 0x10)
                 value = 0x1b;  //remap DP reg
         else
                 if ( (value & 0x1f) > 0x10)
                         value = (value & 0x1f) - 1;
         opreg( value & 0x1f );
 }
        return true;
}

//----------------------------------------------------------------------
static bool S_regs(int value)
{

        if ( D_regs( value ) )
        {
                op++;
                return true;
        }
        else
                return false;

}
//----------------------------------------------------------------------
static bool D_R(int value)      // Интерпретация номеров регистров Rx
{

        if ( D_regs(value & 0x07) )
                return true;
        else
                return false;
}
//----------------------------------------------------------------------
static bool S_R(int value)
{

        if ( D_R(value) )
        {
                op++;
                return true;
        }
        else
                return false;
}
//----------------------------------------------------------------------
static bool D_R2(int value)     // Интерпретация номеров регистров Rx
{

        if ( D_regs(r2 + (value & 0x07)) )
                return true;
        else
                return false;
}
//----------------------------------------------------------------------
static bool D_ar(int value)     // Интерпретация номеров регистров arx
{

        if ( D_regs(ar0 + (value & 0x07)) )
                return true;
        else
                return false;
}
//----------------------------------------------------------------------
static bool S_ar(int value)     // Интерпретация номеров регистров arx
{

        if ( D_ar( value ) )
        {
                op++;
                return true;
        }
        else
                return false;
}

//----------------------------------------------------------------------
static bool D_indir(int value)  // Косвеннная адресация
{
  op->type   = o_phrase;
  op->dtyp   = dt_byte;
  op->phrase = ( value & 0xf800 ) >> 11;                // тип косвеннная адресации
  op->phtype = ar0 + ((value >> 8) & 0x07);             // номер регистра
  op->addr = value & 0xff;                                              // смещение (если есть)
  return true;

}
//----------------------------------------------------------------------
static bool S_indir(int value)
{

        if ( D_indir( value ) )
        {
                op++;
                return true;
        }
        else
                return false;

}
//----------------------------------------------------------------------
static bool D_indir3(int value) // Косвеннная адресация для 3х Операндных и для паралл команд
{

  op->type   = o_phrase;
  op->dtyp   = dt_byte;
  op->phrase = ( value & 0xf8 ) >> 3;   // тип косвеннная адресации
  op->phtype = ar0 + (value  & 0x07);   // номер регистра
  op->addr = 1;                                                 // смещение (если есть)
  return true;

}
//----------------------------------------------------------------------
static bool S_indir3(int value)
{

        if ( D_indir3( value ) )
        {
                op++;
                return true;
        }
        else
                return false;
}

//----------------------------------------------------------------------
static bool SSD_src3(int value) // Разбор для 3х-операндных команд
{

switch( (value >> 16) & 0x60)
    {
       case 0x00:
                S_regs(value & 0xff);
                S_regs((value >> 8) & 0xff);
                D_regs((value >> 16) & 0x1f);
                break;

       case 0x20:
                S_regs(value & 0xff);
                S_indir3((value >> 8) & 0xff);
                D_regs((value >> 16) & 0x1f);
                break;

       case 0x40:
                S_indir3(value & 0xff);
                S_regs((value >> 8) & 0xff);
                D_regs((value >> 16) & 0x1f);
                break;

       case 0x60:
                S_indir3(value & 0xff);
                S_indir3((value >> 8) & 0xff);
                D_regs((value >> 16) & 0x1f);
                break;

       default:   return false;
    }
    return true;
}

//----------------------------------------------------------------------
static bool SD_src3_2op(int value)      // Разбор для 3х-операндных команд, из которых исп. только 2
{

switch( (value >> 16) & 0x60)
    {
       case 0x00:
                S_regs(value & 0xff);
                D_regs((value >> 8) & 0xff);
                break;
       case 0x20:
                S_regs(value & 0xff);
                D_indir3((value >> 8) & 0xff);
                break;
       case 0x40:
                S_indir3(value & 0xff);
                D_regs((value >> 8) & 0xff);
                break;
       case 0x60:
                S_indir3(value & 0xff);
                D_indir3((value >> 8) & 0xff);
                break;
       default:   return false;
    }
        return true;
}

//----------------------------------------------------------------------
static bool DBranch(int /*value*/)      // Установить признак отложенного перехода
{
        cmd.auxpref |= DBrFlag;         //delayed branch
        return true;
}

//----------------------------------------------------------------------
static bool ImmFlt(int /*value*/)       // Установить признак float константы
{
        cmd.auxpref |= ImmFltFlag;              //delayed branch
        return true;
}

//----------------------------------------------------------------------
static bool cond(int value)     // Интерпретация кодов условий
{

        if ( ((value & 0x1f) > 0x14 ) || ((value & 0x1f) ==  0x0b ) )
                return false;

        cmd.auxpref |= value & 0x1f;

        if ( (cmd.auxpref & 0x1f) == 0) // Upgrade retscond to retsu

                switch( cmd.itype )
                {

                 case TMS320C3X_RETIcond:
                        cmd.itype = TMS320C3X_RETIU;
                        break;

                 case TMS320C3X_RETScond:
                        cmd.itype = TMS320C3X_RETSU;
                        break;
                };



        if ( value & 0x20 )
                DBranch(0);     //delayed branch

        return true;
}
//----------------------------------------------------------------------
static bool SD_adres(int value) // Главная адресация
{

 switch ( (value >> 16) & 0x60 )
    {
       case 0x00:
                S_regs(value & 0xff);
                D_regs((value >> 16) & 0x1f);
                break;

       case 0x20:
                op->addr = value & 0xffff;
                make_o_mem();
                op++;
                D_regs((value >> 16) & 0x1f);
                break;

       case 0x40:
                S_indir(value & 0xffff);
                D_regs((value >> 16) & 0x1f);
                break;

       case 0x60:
                op->type  = o_imm;
                op->dtyp  = dt_word;
                op->value = value & 0xffff;
                op++;
                D_regs((value >> 16) & 0x1f);
                break;

       default:   return false;
    }
        return true;

}

//----------------------------------------------------------------------
static bool SD_adresRev(int value)      // Главная адресация с обратным порядком операндов
{

 switch ( (value >> 16) & 0x60 )
    {
       case 0x00:
                S_regs((value >> 16) & 0x1f);
                D_regs(value & 0xff);
                break;

       case 0x20:
                S_regs((value >> 16) & 0x1f);
                op->addr = value & 0xffff;
                make_o_mem();
                break;

       case 0x40:
                S_regs((value >> 16) & 0x1f);
                D_indir(value & 0xffff);
                break;

       case 0x60:
                S_regs((value >> 16) & 0x1f);
                op->type  = o_imm;
                op->dtyp  = dt_word;
                op->value = value & 0xffff;
                break;

       default:   return false;
    }
        return true;
}
//----------------------------------------------------------------------
static bool D_adres_1Op(int value) // Главная адресация с использованием только одного операнда
{

 switch ( (value >> 16) & 0x60 )
    {
       case 0x00:
                D_regs(value & 0xffff);
                break;
       case 0x20:
                op->addr = value & 0xffff;
                make_o_mem();
                break;
       case 0x40:
                D_indir(value & 0xffff);
                break;
       case 0x60:
                op->type  = o_imm;
                op->dtyp  = dt_word;
                op->value = value & 0xffff;
                break;
       default:   return false;
    }
        return true;
}

//----------------------------------------------------------------------
static bool idle_1_2(int value)
{
        if ( value & 0x01 )
                cmd.itype = TMS320C3X_IDLE2;
        else
                cmd.itype = TMS320C3X_IDLE;
        return true;
}

//----------------------------------------------------------------------
static bool speedctrl(int value)
{
        if ( value & 0x01 )
                cmd.itype = TMS320C3X_LOPOWER;
        else
                cmd.itype = TMS320C3X_MAXSPEED;
        return true;
}

//----------------------------------------------------------------------
static bool nopcases(int value)
{
        if ( ((value>>16) & 0x60)==0x40 )
                 D_adres_1Op(value);

        return true;
}
//----------------------------------------------------------------------

static opcode table[] =
{
        { TMS320C3X_ABSF,        0x000, {{ SD_adres,            0x007fffff }, { ImmFlt,         0x00000000 } }},
        { TMS320C3X_ABSI,        0x001, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_ADDC,        0x002, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_ADDF,        0x003, {{ SD_adres,            0x007fffff }, { ImmFlt,         0x00000000 } }},
        { TMS320C3X_ADDI,        0x004, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_AND,         0x005, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_ANDN,        0x006, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_ASH,         0x007, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_CMPF,        0x008, {{ SD_adres,            0x007fffff }, { ImmFlt,         0x00000000 } }},
        { TMS320C3X_CMPI,        0x009, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_FIX,         0x00a, {{ SD_adres,            0x007fffff }, { ImmFlt,         0x00000000 } }},
        { TMS320C3X_FLOAT,       0x00b, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_NONE,        0x00c, {{ idle_1_2,            0xffffffff } }},//двойственный случай надо дальше просматривать маску
        { TMS320C3X_LDE,         0x00d, {{ SD_adres,            0x007fffff }, { ImmFlt,         0x00000000 } }},
        { TMS320C3X_LDF,         0x00e, {{ SD_adres,            0x007fffff }, { ImmFlt,         0x00000000 } }},
        { TMS320C3X_LDFI,        0x00f, {{ SD_adres,            0x007fffff }, { ImmFlt,         0x00000000 } }},
        { TMS320C3X_LDI,         0x010, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_LDII,        0x011, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_LDM,         0x012, {{ SD_adres,            0x007fffff }, { ImmFlt,         0x00000000 } }},
        { TMS320C3X_LSH,         0x013, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_MPYF,        0x014, {{ SD_adres,            0x007fffff }, { ImmFlt,         0x00000000 } }},
        { TMS320C3X_MPYI,        0x015, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_NEGB,        0x016, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_NEGF,        0x017, {{ SD_adres,            0x007fffff }, { ImmFlt,         0x00000000 } }},
        { TMS320C3X_NEGI,        0x018, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_NOP,         0x019, {{ nopcases,            0x007fffff } }},// случай с возможными update registers
        { TMS320C3X_NORM,        0x01a, {{ SD_adres,            0x007fffff }, { ImmFlt,         0x00000000 } }},
        { TMS320C3X_NOT,         0x01b, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_POP,         0x01c, {{ D_regs,              0x001f0000 } }},
        { TMS320C3X_POPF,        0x01d, {{ D_regs,              0x001f0000 } }},
        { TMS320C3X_PUSH,        0x01e, {{ D_regs,              0x001f0000 } }},
        { TMS320C3X_PUSHF,       0x01f, {{ D_regs,              0x001f0000 } }},
        { TMS320C3X_OR,          0x020, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_NONE,        0x021, {{ speedctrl,           0xffffffff } }},//двойственный случай надо дальше просматривать маску
        { TMS320C3X_RND,         0x022, {{ SD_adres,            0x007fffff }, { ImmFlt,         0x00000000 } }},
        { TMS320C3X_ROL,         0x023, {{ D_regs,              0x001f0000 } }},
        { TMS320C3X_ROLC,        0x024, {{ D_regs,              0x001f0000 } }},
        { TMS320C3X_ROR,         0x025, {{ D_regs,              0x001f0000 } }},
        { TMS320C3X_RORC,        0x026, {{ D_regs,              0x001f0000 } }},
        { TMS320C3X_RPTS,        0x027, {{ D_adres_1Op,         0x007fffff } }},
        { TMS320C3X_STF,         0x028, {{ SD_adresRev,         0x007fffff } }},
        { TMS320C3X_STFI,        0x029, {{ SD_adresRev,         0x007fffff } }},
        { TMS320C3X_STI,         0x02a, {{ SD_adresRev,         0x007fffff } }},
        { TMS320C3X_STII,        0x02b, {{ SD_adresRev,         0x007fffff } }},
        { TMS320C3X_SIGI,        0x02c  },
        { TMS320C3X_SUBB,        0x02d, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_SUBC,        0x02e, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_SUBF,        0x02f, {{ SD_adres,            0x007fffff }, { ImmFlt,         0x00000000 } }},
        { TMS320C3X_SUBI,        0x030, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_SUBRB,       0x031, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_SUBRF,       0x032, {{ SD_adres,            0x007fffff }, { ImmFlt,         0x00000000 } }},
        { TMS320C3X_SUBRI,       0x033, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_TSTB,        0x034, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_XOR,         0x035, {{ SD_adres,            0x007fffff } }},
        { TMS320C3X_IACK,        0x036  },
        { TMS320C3X_null,        0x037  },{ TMS320C3X_null,      0x038  }, { TMS320C3X_null,     0x039  },      { TMS320C3X_null,        0x03a  },//недопустимое значение
        { TMS320C3X_null,        0x03b  },{ TMS320C3X_null,      0x03c  }, { TMS320C3X_null,     0x03d  },      { TMS320C3X_null,        0x03e  },//недопустимое значение
        { TMS320C3X_null,        0x03f  },//недопустимое значение
//трехоперандные команды
        { TMS320C3X_ADDC3,       0x040, {{ SSD_src3,            0x007fffff } }},
        { TMS320C3X_ADDF3,       0x041, {{ SSD_src3,            0x007fffff } }},
        { TMS320C3X_ADDI3,       0x042, {{ SSD_src3,            0x007fffff } }},
        { TMS320C3X_AND3,        0x043, {{ SSD_src3,            0x007fffff } }},
        { TMS320C3X_ANDN3,       0x044, {{ SSD_src3,            0x007fffff } }},
        { TMS320C3X_ASH3,        0x045, {{ SSD_src3,            0x007fffff } }},
        { TMS320C3X_CMPF3,       0x046, {{ SD_src3_2op,         0x007fffff } }},
        { TMS320C3X_CMPI3,       0x047, {{ SD_src3_2op,         0x007fffff } }},
        { TMS320C3X_LSH3,        0x048, {{ SSD_src3,            0x007fffff } }},
        { TMS320C3X_MPYF3,       0x049, {{ SSD_src3,            0x007fffff } }},
        { TMS320C3X_MPYI3,       0x04a, {{ SSD_src3,            0x007fffff } }},
        { TMS320C3X_OR3,         0x04b, {{ SSD_src3,            0x007fffff } }},
        { TMS320C3X_SUBB3,       0x04c, {{ SSD_src3,            0x007fffff } }},
        { TMS320C3X_SUBF3,       0x04d, {{ SSD_src3,            0x007fffff } }},
        { TMS320C3X_SUBI3,       0x04e, {{ SSD_src3,            0x007fffff } }},
        { TMS320C3X_TSTB3,       0x04f, {{ SD_src3_2op,         0x007fffff } }},
        { TMS320C3X_XOR3,        0x050, {{ SSD_src3,            0x007fffff } }},
        { TMS320C3X_null,        0x051  },{ TMS320C3X_null,      0x052  },{ TMS320C3X_null,      0x053  },{ TMS320C3X_null,      0x054  },//недопустимое значение
        { TMS320C3X_null,        0x055  },{ TMS320C3X_null,      0x056  },{ TMS320C3X_null,      0x057  },{ TMS320C3X_null,      0x058  },//недопустимое значение
        { TMS320C3X_null,        0x059  },{ TMS320C3X_null,      0x05a  },{ TMS320C3X_null,      0x05b  },{ TMS320C3X_null,      0x05c  },//недопустимое значение
        { TMS320C3X_null,        0x05d  },{ TMS320C3X_null,      0x05e  },{ TMS320C3X_null,      0x05f  },{ TMS320C3X_null,      0x060  },//недопустимое значение
        { TMS320C3X_null,        0x061  },{ TMS320C3X_null,      0x062  },{ TMS320C3X_null,      0x063  },{ TMS320C3X_null,      0x064  },//недопустимое значение
        { TMS320C3X_null,        0x065  },{ TMS320C3X_null,      0x066  },{ TMS320C3X_null,      0x067  },{ TMS320C3X_null,      0x068  },//недопустимое значение
        { TMS320C3X_null,        0x069  },{ TMS320C3X_null,      0x06a  },{ TMS320C3X_null,      0x06b  },{ TMS320C3X_null,      0x06c  },//недопустимое значение
        { TMS320C3X_null,        0x06d  },{ TMS320C3X_null,      0x06e  },{ TMS320C3X_null,      0x06f  },{ TMS320C3X_null,      0x070  },//недопустимое значение
        { TMS320C3X_null,        0x071  },{ TMS320C3X_null,      0x072  },{ TMS320C3X_null,      0x073  },{ TMS320C3X_null,      0x074  },//недопустимое значение
        { TMS320C3X_null,        0x075  },{ TMS320C3X_null,      0x076  },{ TMS320C3X_null,      0x077  },{ TMS320C3X_null,      0x078  },//недопустимое значение
        { TMS320C3X_null,        0x079  },{ TMS320C3X_null,      0x07a  },{ TMS320C3X_null,      0x07b  },{ TMS320C3X_null,      0x07c  },//недопустимое значение
        { TMS320C3X_null,        0x07d  },{ TMS320C3X_null,      0x07e  },{ TMS320C3X_null,      0x07f  },//недопустимое значение
//0x80 - 0x8f LDFcond
        { TMS320C3X_MV_IDX,      0x09f  },{ TMS320C3X_MV_IDX, 0x09f  }, { TMS320C3X_MV_IDX,      0x09f  },{ TMS320C3X_MV_IDX, 0x09f  },
        { TMS320C3X_MV_IDX,      0x09f  },{ TMS320C3X_MV_IDX, 0x09f  }, { TMS320C3X_MV_IDX,      0x09f  },{ TMS320C3X_MV_IDX, 0x09f  },
        { TMS320C3X_MV_IDX,      0x09f  },{ TMS320C3X_MV_IDX, 0x09f  }, { TMS320C3X_MV_IDX,      0x09f  },{ TMS320C3X_MV_IDX, 0x09f  },
        { TMS320C3X_MV_IDX,      0x09f  },{ TMS320C3X_MV_IDX, 0x09f  }, { TMS320C3X_MV_IDX,      0x09f  },{ TMS320C3X_MV_IDX, 0x09f  },
//0x90 - 0x9f LDFcond
        { TMS320C3X_MV_IDX,      0x09f  },{ TMS320C3X_MV_IDX, 0x09f  }, { TMS320C3X_MV_IDX,      0x09f  },{ TMS320C3X_MV_IDX, 0x09f  },
        { TMS320C3X_MV_IDX,      0x09f  },{ TMS320C3X_MV_IDX, 0x09f  }, { TMS320C3X_MV_IDX,      0x09f  },{ TMS320C3X_MV_IDX, 0x09f  },
        { TMS320C3X_MV_IDX,      0x09f  },{ TMS320C3X_MV_IDX, 0x09f  }, { TMS320C3X_MV_IDX,      0x09f  },{ TMS320C3X_MV_IDX, 0x09f  },
        { TMS320C3X_MV_IDX,      0x09f  },{ TMS320C3X_MV_IDX, 0x09f  }, { TMS320C3X_MV_IDX,      0x09f  },
        { TMS320C3X_LDFcond,     0x09f, {{ cond,        0x0f800000 }, { SD_adres,       0x007fffff }, { ImmFlt,         0x00000000 } }},
//0xa0 - 0xaf LDIcond
        { TMS320C3X_MV_IDX,      0x0bf  },{ TMS320C3X_MV_IDX, 0x0bf  },{ TMS320C3X_MV_IDX,       0x0bf  },{ TMS320C3X_MV_IDX, 0x0bf  },
        { TMS320C3X_MV_IDX,      0x0bf  },{ TMS320C3X_MV_IDX, 0x0bf  },{ TMS320C3X_MV_IDX,       0x0bf  },{ TMS320C3X_MV_IDX, 0x0bf  },
        { TMS320C3X_MV_IDX,      0x0bf  },{ TMS320C3X_MV_IDX, 0x0bf  },{ TMS320C3X_MV_IDX,       0x0bf  },{ TMS320C3X_MV_IDX, 0x0bf  },
        { TMS320C3X_MV_IDX,      0x0bf  },{ TMS320C3X_MV_IDX, 0x0bf  },{ TMS320C3X_MV_IDX,       0x0bf  },{ TMS320C3X_MV_IDX, 0x0bf  },
//0xb0 - 0xbf LDIcond
        { TMS320C3X_MV_IDX,      0x0bf  },{ TMS320C3X_MV_IDX, 0x0bf  },{ TMS320C3X_MV_IDX,       0x0bf  },{ TMS320C3X_MV_IDX, 0x0bf  },
        { TMS320C3X_MV_IDX,      0x0bf  },{ TMS320C3X_MV_IDX, 0x0bf  },{ TMS320C3X_MV_IDX,       0x0bf  },{ TMS320C3X_MV_IDX, 0x0bf  },
        { TMS320C3X_MV_IDX,      0x0bf  },{ TMS320C3X_MV_IDX, 0x0bf  },{ TMS320C3X_MV_IDX,       0x0bf  },{ TMS320C3X_MV_IDX, 0x0bf  },
        { TMS320C3X_MV_IDX,      0x0bf  },{ TMS320C3X_MV_IDX, 0x0bf  },{ TMS320C3X_MV_IDX,       0x0bf  },
        { TMS320C3X_LDIcond,     0x0bf, {{ cond,        0x0f800000 }, { SD_adres,       0x007fffff } }},
//0xc0 - 0xc1 BR
        { TMS320C3X_MV_IDX,      0x0c1  },
        { TMS320C3X_BR,          0x0c1, {{ D_adr24,     0x00ffffff } }},
//0xc2 - 0xc3 BR
        { TMS320C3X_MV_IDX,      0x0c3  },
        { TMS320C3X_BRD,         0x0c3, {{ DBranch,     0x00000000 }, { D_adr24,        0x00ffffff } }},
//0xc4 - 0xc5 CALL
        { TMS320C3X_MV_IDX,      0x0c5  },
        { TMS320C3X_CALL,        0x0c5, {{ D_adr24,     0x00ffffff } }},
        { TMS320C3X_null,        0x0c6  },//недопустимое значение
        { TMS320C3X_null,        0x0c7  },//недопустимое значение
//0xc8 - 0xc9 RPTB
        { TMS320C3X_MV_IDX,      0x0c9  },
        { TMS320C3X_RPTB,        0x0c9, {{ D_adr24,                     0x00ffffff } }},
        { TMS320C3X_null,        0x0ca  },//недопустимое значение
        { TMS320C3X_null,        0x0cb  },//недопустимое значение
        { TMS320C3X_SWI,         0x0cc  },
        { TMS320C3X_null,        0x0cd  },//недопустимое значение
        { TMS320C3X_null,        0x0ce  },//недопустимое значение
        { TMS320C3X_null,        0x0cf  },//недопустимое значение
        { TMS320C3X_Bcond,       0x0d0, {{ cond,        0x003f0000 }, { D_regs,         0x0000ffff } }},
        { TMS320C3X_null,        0x0d1  },//недопустимое значение
        { TMS320C3X_null,        0x0d2  },//недопустимое значение
        { TMS320C3X_null,        0x0d3  },//недопустимое значение
        { TMS320C3X_Bcond,       0x0d4, {{ cond,        0x003f0000 }, { D_PC_Displ,     0x0020ffff } }},
        { TMS320C3X_null,        0x0d5  },//недопустимое значение
        { TMS320C3X_null,        0x0d6  },//недопустимое значение
        { TMS320C3X_null,        0x0d7  },//недопустимое значение
//0xd8 - 0xdb DBcond
        { TMS320C3X_MV_IDX,      0x0db  },
        { TMS320C3X_MV_IDX,      0x0db  },
        { TMS320C3X_MV_IDX,      0x0db  },
        { TMS320C3X_DBcond,      0x0db, {{ cond,        0x003f0000 }, { S_ar,   0x01c00000 }, { D_regs,         0x0000ffff } }},
//0xdc - 0xdf DBcond
        { TMS320C3X_MV_IDX,      0x0df  },
        { TMS320C3X_MV_IDX,      0x0df  },
        { TMS320C3X_MV_IDX,      0x0df  },
        { TMS320C3X_DBcond,      0x0df, {{ cond,        0x003f0000 }, { S_ar,   0x01c00000 }, { D_PC_Displ,     0x0020ffff } }},
        { TMS320C3X_CALLcond,    0x0e0, {{ cond,        0x001f0000 }, { D_regs,         0x0000ffff } }},
        { TMS320C3X_null,        0x0e1  },//недопустимое значение
        { TMS320C3X_null,        0x0e2  },//недопустимое значение
        { TMS320C3X_null,        0x0e3  },//недопустимое значение
        { TMS320C3X_CALLcond,    0x0e4, {{ cond,        0x001f0000 }, { D_PC_Displ,     0x0000ffff } }},
        { TMS320C3X_null,        0x0e5  },//недопустимое значение
        { TMS320C3X_null,        0x0e6  },//недопустимое значение
        { TMS320C3X_null,        0x0e7  },//недопустимое значение
        { TMS320C3X_TRAPcond,    0x0e8, {{ cond,        0x001f0000 }, { imm8,           0x0000001f } }},
        { TMS320C3X_null,        0x0e9  },//недопустимое значение
        { TMS320C3X_null,        0x0ea  },//недопустимое значение
        { TMS320C3X_null,        0x0eb  },//недопустимое значение
        { TMS320C3X_null,        0x0ec  },//недопустимое значение
        { TMS320C3X_null,        0x0ed  },//недопустимое значение
        { TMS320C3X_null,        0x0ee  },//недопустимое значение
        { TMS320C3X_null,        0x0ef  },//недопустимое значение
        { TMS320C3X_RETIcond,    0x0f0, {{ cond,        0x001f0000 } }},
        { TMS320C3X_RETScond,    0x0f1, {{ cond,        0x001f0000 } }},
        { TMS320C3X_null,        0x0f2  },      { TMS320C3X_null,        0x0f3  },      { TMS320C3X_null,        0x0f4  },      { TMS320C3X_null,        0x0f5  },//недопустимое значение
        { TMS320C3X_null,        0x0f6  },      { TMS320C3X_null,        0x0f7  },      { TMS320C3X_null,        0x0f8  },      { TMS320C3X_null,        0x0f9  },//недопустимое значение
        { TMS320C3X_null,        0x0fa  },      { TMS320C3X_null,        0x0fb  },      { TMS320C3X_null,        0x0fc  },      { TMS320C3X_null,        0x0fd  },//недопустимое значение
        { TMS320C3X_null,        0x0fe  },      { TMS320C3X_null,        0x0ff  },//недопустимое значение
        { TMS320C3X_MV_IDX,      0x101  },
        { TMS320C3X_MPYF3,       0x101, {{ S_indir3,    0x0000ff00 }, { S_indir3,       0x000000ff }, { D_R,    0x00800000 }},
          TMS320C3X_ADDF3,                 {{ S_R,      0x00380000 }, { S_R,            0x00070000 }, { D_R2,   0x00400000 }}},
        { TMS320C3X_MV_IDX,      0x103  },
        { TMS320C3X_MPYF3,       0x103, {{ S_indir3,    0x0000ff00 }, { S_R,            0x00380000 }, { D_R,    0x00800000 }},
          TMS320C3X_ADDF3,                 {{ S_indir3, 0x000000ff }, { S_R,            0x00070000 }, { D_R2,   0x00400000 }}},
        { TMS320C3X_MV_IDX,      0x105  },
        { TMS320C3X_MPYF3,       0x105, {{ S_R,         0x00380000 }, { S_R,            0x00070000 }, { D_R,    0x00800000 }},
          TMS320C3X_ADDF3,                 {{ S_indir3, 0x0000ff00 }, { S_indir3,       0x000000ff }, { D_R2,   0x00400000 }}},
        { TMS320C3X_MV_IDX,      0x107  },
        { TMS320C3X_MPYF3,       0x107, {{ S_indir3,    0x0000ff00 }, { S_R,            0x00380000 }, { D_R,    0x00800000 }},
          TMS320C3X_ADDF3,                 {{ S_R,      0x00070000 }, { S_indir3,       0x000000ff }, { D_R2,   0x00400000 }}},
        { TMS320C3X_MV_IDX,      0x109  },
        { TMS320C3X_MPYF3,       0x109, {{ S_indir3,    0x0000ff00 }, { S_indir3,       0x000000ff }, { D_R,    0x00800000 }},
          TMS320C3X_SUBF3,                 {{ S_R,      0x00380000 }, { S_R,            0x00070000 }, { D_R2,   0x00400000 }}},
        { TMS320C3X_MV_IDX,      0x10b  },
        { TMS320C3X_MPYF3,       0x10b, {{ S_indir3,    0x0000ff00 }, { S_R,            0x00380000 }, { D_R,    0x00800000 }},
          TMS320C3X_SUBF3,                 {{ S_indir3, 0x000000ff }, { S_R,            0x00070000 }, { D_R2,   0x00400000 }}},
        { TMS320C3X_MV_IDX,      0x10d  },
        { TMS320C3X_MPYF3,       0x10d, {{ S_R,         0x00380000 }, { S_R,            0x00070000 }, { D_R,    0x00800000 }},
          TMS320C3X_SUBF3,                 {{ S_indir3, 0x0000ff00 }, { S_indir3,       0x000000ff }, { D_R2,   0x00400000 }}},
        { TMS320C3X_MV_IDX,      0x10f  },
        { TMS320C3X_MPYF3,       0x10f, {{ S_indir3,    0x0000ff00 }, { S_R,            0x00380000 }, { D_R,    0x00800000 }},
          TMS320C3X_SUBF3,                 {{ S_R,      0x00070000 }, { S_indir3,       0x000000ff }, { D_R2,   0x00400000 }}},
        { TMS320C3X_MV_IDX,      0x111  },
        { TMS320C3X_MPYI3,       0x111, {{ S_indir3,    0x0000ff00 }, { S_indir3,       0x000000ff }, { D_R,    0x00800000 }},
          TMS320C3X_ADDI3,                 {{ S_R,      0x00380000 }, { S_R,            0x00070000 }, { D_R2,   0x00400000 }}},
        { TMS320C3X_MV_IDX,      0x113  },
        { TMS320C3X_MPYI3,       0x113, {{ S_indir3,    0x0000ff00 }, { S_R,            0x00380000 }, { D_R,    0x00800000 }},
          TMS320C3X_ADDI3,                 {{ S_indir3, 0x000000ff }, { S_R,            0x00070000 }, { D_R2,   0x00400000 }}},
        { TMS320C3X_MV_IDX,      0x115  },
        { TMS320C3X_MPYI3,       0x115, {{ S_R,         0x00380000 }, { S_R,            0x00070000 }, { D_R,    0x00800000 }},
          TMS320C3X_ADDI3,                 {{ S_indir3, 0x0000ff00 }, { S_indir3,       0x000000ff }, { D_R2,   0x00400000 }}},
        { TMS320C3X_MV_IDX,      0x117  },
        { TMS320C3X_MPYI3,       0x117, {{ S_indir3,    0x0000ff00 }, { S_R,            0x00380000 }, { D_R,    0x00800000 }},
          TMS320C3X_ADDI3,                 {{ S_R,      0x00070000 }, { S_indir3,       0x000000ff }, { D_R2,   0x00400000 }}},
        { TMS320C3X_MV_IDX,      0x119  },
        { TMS320C3X_MPYI3,       0x119, {{ S_indir3,    0x0000ff00 }, { S_indir3,       0x000000ff }, { D_R,    0x00800000 }},
          TMS320C3X_SUBI3,                 {{ S_R,      0x00380000 }, { S_R,            0x00070000 }, { D_R2,   0x00400000 }}},
        { TMS320C3X_MV_IDX,      0x11b  },
        { TMS320C3X_MPYI3,       0x11b, {{ S_indir3,    0x0000ff00 }, { S_R,            0x00380000 }, { D_R,    0x00800000 }},
          TMS320C3X_SUBI3,                 {{ S_indir3, 0x000000ff }, { S_R,            0x00070000 }, { D_R2,   0x00400000 }}},
        { TMS320C3X_MV_IDX,      0x11d  },
        { TMS320C3X_MPYI3,       0x11d, {{ S_R,         0x00380000 }, { S_R,            0x00070000 }, { D_R,    0x00800000 }},
          TMS320C3X_SUBI3,                 {{ S_indir3, 0x0000ff00 }, { S_indir3,       0x000000ff }, { D_R2,   0x00400000 }}},
        { TMS320C3X_MV_IDX,      0x11f  },
        { TMS320C3X_MPYI3,       0x11f, {{ S_indir3,    0x0000ff00 }, { S_R,            0x00380000 }, { D_R,    0x00800000 }},
          TMS320C3X_SUBI3,                 {{ S_R,      0x00070000 }, { S_indir3,       0x000000ff }, { D_R2,   0x00400000 }}},

        { TMS320C3X_null,        0x120  },      { TMS320C3X_null,        0x121  },      { TMS320C3X_null,        0x122  },      { TMS320C3X_null,        0x123  },//недопустимое значение
        { TMS320C3X_null,        0x124  },      { TMS320C3X_null,        0x125  },      { TMS320C3X_null,        0x126  },      { TMS320C3X_null,        0x127  },//недопустимое значение
        { TMS320C3X_null,        0x128  },      { TMS320C3X_null,        0x129  },      { TMS320C3X_null,        0x12a  },      { TMS320C3X_null,        0x12b  },//недопустимое значение
        { TMS320C3X_null,        0x12c  },      { TMS320C3X_null,        0x12d  },      { TMS320C3X_null,        0x12e  },      { TMS320C3X_null,        0x12f  },//недопустимое значение
        { TMS320C3X_null,        0x130  },      { TMS320C3X_null,        0x131  },      { TMS320C3X_null,        0x132  },      { TMS320C3X_null,        0x133  },//недопустимое значение
        { TMS320C3X_null,        0x134  },      { TMS320C3X_null,        0x135  },      { TMS320C3X_null,        0x136  },      { TMS320C3X_null,        0x137  },//недопустимое значение
        { TMS320C3X_null,        0x138  },      { TMS320C3X_null,        0x139  },      { TMS320C3X_null,        0x13a  },      { TMS320C3X_null,        0x13b  },//недопустимое значение
        { TMS320C3X_null,        0x13c  },      { TMS320C3X_null,        0x13d  },      { TMS320C3X_null,        0x13e  },      { TMS320C3X_null,        0x13f  },//недопустимое значение
        { TMS320C3X_null,        0x140  },      { TMS320C3X_null,        0x141  },      { TMS320C3X_null,        0x142  },      { TMS320C3X_null,        0x143  },//недопустимое значение
        { TMS320C3X_null,        0x144  },      { TMS320C3X_null,        0x145  },      { TMS320C3X_null,        0x146  },      { TMS320C3X_null,        0x147  },//недопустимое значение
        { TMS320C3X_null,        0x148  },      { TMS320C3X_null,        0x149  },      { TMS320C3X_null,        0x14a  },      { TMS320C3X_null,        0x14b  },//недопустимое значение
        { TMS320C3X_null,        0x14c  },      { TMS320C3X_null,        0x14d  },      { TMS320C3X_null,        0x14e  },      { TMS320C3X_null,        0x14f  },//недопустимое значение
        { TMS320C3X_null,        0x150  },      { TMS320C3X_null,        0x151  },      { TMS320C3X_null,        0x152  },      { TMS320C3X_null,        0x153  },//недопустимое значение
        { TMS320C3X_null,        0x154  },      { TMS320C3X_null,        0x155  },      { TMS320C3X_null,        0x156  },      { TMS320C3X_null,        0x157  },//недопустимое значение
        { TMS320C3X_null,        0x158  },      { TMS320C3X_null,        0x159  },      { TMS320C3X_null,        0x15a  },      { TMS320C3X_null,        0x15b  },//недопустимое значение
        { TMS320C3X_null,        0x15c  },      { TMS320C3X_null,        0x15d  },      { TMS320C3X_null,        0x15e  },      { TMS320C3X_null,        0x15f  },//недопустимое значение
        { TMS320C3X_null,        0x160  },      { TMS320C3X_null,        0x161  },      { TMS320C3X_null,        0x162  },      { TMS320C3X_null,        0x163  },//недопустимое значение
        { TMS320C3X_null,        0x164  },      { TMS320C3X_null,        0x165  },      { TMS320C3X_null,        0x166  },      { TMS320C3X_null,        0x167  },//недопустимое значение
        { TMS320C3X_null,        0x168  },      { TMS320C3X_null,        0x169  },      { TMS320C3X_null,        0x16a  },      { TMS320C3X_null,        0x16b  },//недопустимое значение
        { TMS320C3X_null,        0x16c  },      { TMS320C3X_null,        0x16d  },      { TMS320C3X_null,        0x16e  },      { TMS320C3X_null,        0x16f  },//недопустимое значение
        { TMS320C3X_null,        0x170  },      { TMS320C3X_null,        0x171  },      { TMS320C3X_null,        0x172  },      { TMS320C3X_null,        0x123  },//недопустимое значение
        { TMS320C3X_null,        0x174  },      { TMS320C3X_null,        0x175  },      { TMS320C3X_null,        0x176  },      { TMS320C3X_null,        0x127  },//недопустимое значение
        { TMS320C3X_null,        0x178  },      { TMS320C3X_null,        0x179  },      { TMS320C3X_null,        0x17a  },      { TMS320C3X_null,        0x12b  },//недопустимое значение
        { TMS320C3X_null,        0x17c  },      { TMS320C3X_null,        0x17d  },      { TMS320C3X_null,        0x17e  },      { TMS320C3X_null,        0x12f  },//недопустимое значение

        { TMS320C3X_MV_IDX,     0x183  },
        { TMS320C3X_MV_IDX,     0x183  },
        { TMS320C3X_MV_IDX,     0x183  },
        { TMS320C3X_STF,        0x183, {{ S_R,          0x01c00000 }, { D_indir3,       0x000000ff }},
          TMS320C3X_STF,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x187  },
        { TMS320C3X_MV_IDX,     0x187  },
        { TMS320C3X_MV_IDX,     0x187  },
        { TMS320C3X_STI,        0x187, {{ S_R,          0x01c00000 }, { D_indir3,       0x000000ff }},
          TMS320C3X_STI,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x18b  },
        { TMS320C3X_MV_IDX,     0x18b  },
        { TMS320C3X_MV_IDX,     0x18b  },
        { TMS320C3X_LDF,        0x18b, {{ S_indir3,     0x000000ff }, { D_R,            0x01c00000 }},
          TMS320C3X_LDF,                   {{ S_indir3, 0x0000ff00 }, { D_R,            0x00070000 }}},
        { TMS320C3X_MV_IDX,     0x18f  },
        { TMS320C3X_MV_IDX,     0x18f  },
        { TMS320C3X_MV_IDX,     0x18f  },
        { TMS320C3X_LDI,        0x18f, {{ S_indir3,     0x000000ff }, { D_R,            0x01c00000 }},
          TMS320C3X_LDI,                   {{ S_indir3, 0x0000ff00 }, { D_R,            0x00070000 }}},
        { TMS320C3X_MV_IDX,     0x193  },
        { TMS320C3X_MV_IDX,     0x193  },
        { TMS320C3X_MV_IDX,     0x193  },
        { TMS320C3X_ABSF,       0x193, {{ S_indir3,     0x000000ff }, { D_R,            0x01c00000 }},
          TMS320C3X_STF,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x197  },
        { TMS320C3X_MV_IDX,     0x197  },
        { TMS320C3X_MV_IDX,     0x197  },
        { TMS320C3X_ABSI,       0x197, {{ S_indir3,     0x000000ff }, { D_R,            0x01c00000 }},
          TMS320C3X_STI,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x19b  },
        { TMS320C3X_MV_IDX,     0x19b  },
        { TMS320C3X_MV_IDX,     0x19b  },
        { TMS320C3X_ADDF3,      0x19b, {{ S_indir3,     0x000000ff }, { S_R,            0x00380000 }, { D_R,            0x01c00000 }},
          TMS320C3X_STF,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x19f  },
        { TMS320C3X_MV_IDX,     0x19f  },
        { TMS320C3X_MV_IDX,     0x19f  },
        { TMS320C3X_ADDI3,      0x19f, {{ S_indir3,     0x000000ff }, { S_R,            0x00380000 }, { D_R,            0x01c00000 }},
          TMS320C3X_STI,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x1a3  },
        { TMS320C3X_MV_IDX,     0x1a3  },
        { TMS320C3X_MV_IDX,     0x1a3  },
        { TMS320C3X_AND3,       0x1a3, {{ S_indir3,     0x000000ff }, { S_R,            0x00380000 }, { D_R,            0x01c00000 }},
          TMS320C3X_STI,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x1a7  },
        { TMS320C3X_MV_IDX,     0x1a7  },
        { TMS320C3X_MV_IDX,     0x1a7  },
        { TMS320C3X_ASH3,       0x1a7, {{ S_R,          0x00380000 }, { S_indir3,       0x000000ff }, { D_R,            0x01c00000 }},
          TMS320C3X_STI,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x1ab  },
        { TMS320C3X_MV_IDX,     0x1ab  },
        { TMS320C3X_MV_IDX,     0x1ab  },
        { TMS320C3X_FIX,        0x1ab, {{ S_indir3,     0x000000ff }, { D_R,            0x01c00000 }},
          TMS320C3X_STI,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x1af  },
        { TMS320C3X_MV_IDX,     0x1af  },
        { TMS320C3X_MV_IDX,     0x1af  },
        { TMS320C3X_FLOAT,      0x1af, {{ S_indir3,     0x000000ff }, { D_R,            0x01c00000 }},
          TMS320C3X_STF,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x1b3  },
        { TMS320C3X_MV_IDX,     0x1b3  },
        { TMS320C3X_MV_IDX,     0x1b3  },
        { TMS320C3X_LDF,        0x1b3, {{ S_indir3,     0x000000ff }, { D_R,            0x01c00000 }},
          TMS320C3X_STF,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x1b7  },
        { TMS320C3X_MV_IDX,     0x1b7  },
        { TMS320C3X_MV_IDX,     0x1b7  },
        { TMS320C3X_LDI,        0x1b7, {{ S_indir3,     0x000000ff }, { D_R,            0x01c00000 }},
          TMS320C3X_STI,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x1bb  },
        { TMS320C3X_MV_IDX,     0x1bb  },
        { TMS320C3X_MV_IDX,     0x1bb  },
        { TMS320C3X_LSH3,       0x1bb, {{ S_R,          0x00380000 }, { S_indir3,       0x000000ff }, { D_R,            0x01c00000 }},
          TMS320C3X_STI,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x1bf  },
        { TMS320C3X_MV_IDX,     0x1bf  },
        { TMS320C3X_MV_IDX,     0x1bf  },
        { TMS320C3X_MPYF3,      0x1bf, {{ S_indir3,     0x000000ff }, { S_R,            0x00380000 }, { D_R,            0x01c00000 }},
          TMS320C3X_STF,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x1c3  },
        { TMS320C3X_MV_IDX,     0x1c3  },
        { TMS320C3X_MV_IDX,     0x1c3  },
        { TMS320C3X_MPYI3,      0x1c3, {{ S_indir3,     0x000000ff }, { S_R,            0x00380000 }, { D_R,            0x01c00000 }},
          TMS320C3X_STI,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x1c7  },
        { TMS320C3X_MV_IDX,     0x1c7  },
        { TMS320C3X_MV_IDX,     0x1c7  },
        { TMS320C3X_NEGF,       0x1c7, {{ S_indir3,     0x000000ff }, { D_R,            0x01c00000 }},
          TMS320C3X_STF,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x1cb  },
        { TMS320C3X_MV_IDX,     0x1cb  },
        { TMS320C3X_MV_IDX,     0x1cb  },
        { TMS320C3X_NEGI,       0x1cb, {{ S_indir3,     0x000000ff }, { D_R,            0x01c00000 }},
          TMS320C3X_STI,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x1cf  },
        { TMS320C3X_MV_IDX,     0x1cf  },
        { TMS320C3X_MV_IDX,     0x1cf  },
        { TMS320C3X_NOT,        0x1cf, {{ S_indir3,     0x000000ff }, { D_R,            0x01c00000 }},
          TMS320C3X_STI,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x1d3  },
        { TMS320C3X_MV_IDX,     0x1d3  },
        { TMS320C3X_MV_IDX,     0x1d3  },
        { TMS320C3X_OR3,        0x1d3, {{ S_indir3,     0x000000ff }, { S_R,            0x00380000 }, { D_R,            0x01c00000 }},
          TMS320C3X_STI,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x1d7  },
        { TMS320C3X_MV_IDX,     0x1d7  },
        { TMS320C3X_MV_IDX,     0x1d7  },
        { TMS320C3X_SUBF3,      0x1d7, {{ S_R,          0x00380000 }, { S_indir3,       0x000000ff }, { D_R,            0x01c00000 }},
          TMS320C3X_STF,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x1db  },
        { TMS320C3X_MV_IDX,     0x1db  },
        { TMS320C3X_MV_IDX,     0x1db  },
        { TMS320C3X_SUBI3,      0x1db, {{ S_R,          0x00380000 }, { S_indir3,       0x000000ff }, { D_R,            0x01c00000 }},
          TMS320C3X_STI,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
        { TMS320C3X_MV_IDX,     0x1df  },
        { TMS320C3X_MV_IDX,     0x1df  },
        { TMS320C3X_MV_IDX,     0x1df  },
        { TMS320C3X_XOR3,       0x1df, {{ S_indir3,     0x000000ff }, { S_R,            0x00380000 }, { D_R,            0x01c00000 }},
          TMS320C3X_STI,                   {{ S_R,      0x00070000 }, { D_indir3,       0x0000ff00 }}},
};

//--------------------------------------------------------------------------
static int run_functions(int value, int entry, int start, int end)
{

        for(int j = start; j <= end; j++)
        {
                if ( table[entry].funcs[j].func )
                {

                   if ( false == table[entry].funcs[j].func( (value & table[entry].funcs[j].mask) >> table[entry].funcs[j].shift ) )
                        return false;
                }
                else
                   break;
        }
        return true;
}

//--------------------------------------------------------------------------
int run_functions2(int value, int entry, int start, int end)
{

        for(int j = start; j <= end; j++)
        {
                if ( table[entry].funcs2[j].func )
                {

                   if ( false == table[entry].funcs2[j].func( (value & table[entry].funcs2[j].mask) >> table[entry].funcs2[j].shift) )
                        return false;
                }
                else
                   break;
        }
        return true;
}

//--------------------------------------------------------------------------
int idaapi ana(void)
{
        int     value = get_full_byte(cmd.ea);
        cmd.size++;
        op = &cmd.Op1;

        int idx = (value >> 23) & 0x1ff;

        // ограничения по длине таблицы
        cmd.itype = idx >= qnumber(table) ? TMS320C3X_null : table[idx].itype;

        if ( cmd.itype == TMS320C3X_MV_IDX ) // если это команда перескочить на другую строку таблицы
                cmd.itype = table[ idx = table[idx].cmdidx ].itype;


        if ( cmd.itype != TMS320C3X_null )
        {

                if ( false == run_functions(value, idx, 0, FUNCS_COUNT - 1) )   //запуск ф-ций на исполнение
                        return 0;

                if ( table[idx].ispar )
                {
                        op++;
                        cmd.itype2 = table[ idx = table[idx].cmdidx ].itype2;   // указать код второй инструкции
                        cmd.i2op = op->n;                                                                               // указать место с которого начинаются операнды второй инструкиции

                        if ( false == run_functions2(value, idx, 0, FUNCS_COUNT - 1) )  //запуск ф-ций на исполнение
                                return 0;
                }


                return cmd.size;        // длина всегда 1
        }
        else
                return 0;
}


//--------------------------------------------------------------------------
static void make_masks(void)
{
        int i, j, b;

        for(i = 0; i < sizeof(table)/ sizeof(struct opcode); i++)
        {

    table[i].ispar = (table[i].cmdidx & 0x100) != 0;

                for(j = 0; j < FUNCS_COUNT; j++)
                {
                   if ( table[i].funcs[j].func )
                   {
                      for(b = 0; b < 32; b++)
                      {
                        if ( table[i].funcs[j].mask & (1 << b) )
                           break;
                        else
                           table[i].funcs[j].shift++;
                      }
                   }
                }


                if ( table[i].cmdidx & 0x100 )
                        for(j = 0; j < FUNCS_COUNT; j++)
                        {
                            if ( table[i].funcs2[j].func )
                            {
                                for(b = 0; b < 32; b++)
                                {
                                        if ( table[i].funcs2[j].mask & (1 << b) )
                                                break;
                                        else
                                                table[i].funcs2[j].shift++;
                                }
                            }
                        }

        }
}


//----------------------------------------------------------------------
void init_analyzer(void)
{
  make_masks();
}


//----------------------------------------------------------------------
void interr(const char *module)
{
  const char *name = NULL;
  if ( cmd.itype < TMS320C3X_last )
    name = Instructions[cmd.itype].name;
  else
    cmd.itype = TMS320C3X_null;
  warning("%a(%s): internal error in %s", cmd.ea, name, module);
}
