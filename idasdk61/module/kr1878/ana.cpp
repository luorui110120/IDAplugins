
#include "kr1878.hpp"

#define FUNCS_COUNT 3

struct funcdesc_t
{
  bool (*func)(int);
  int mask;
  int shift;
};

struct opcode
{
  ushort itype;
  const char *recog;
  funcdesc_t funcs[FUNCS_COUNT];
  uint32 mask;
  uint32 value;
};


static op_t *op;       // current operand


//----------------------------------------------------------------------
static uint32 ua_16bits(void)
{
  uint32 x =             get_full_byte(cmd.ea);
  return x;
}


//----------------------------------------------------------------------
inline void opreg(uint16 reg)
{
  op->type = o_reg;
  op->dtyp = dt_word;
  op->reg  = reg;
}

//----------------------------------------------------------------------
static void make_o_mem(void)
{

  switch ( cmd.itype )
  {
    case KR1878_jmp:
    case KR1878_jsr:
    case KR1878_jnz:
    case KR1878_jz:
    case KR1878_jns:
    case KR1878_js:
    case KR1878_jnc:
    case KR1878_jc:

      op->type   = o_near;
      op->dtyp   = dt_code;
      return;
  }
  op->type   = o_mem;
  op->dtyp   = dt_byte;
}


//----------------------------------------------------------------------
static bool D_ddddd(int value)
{
   op->type   = o_phrase;
   op->dtyp   = dt_byte;
   op->reg    = (value >> 3) & 0x03;
   op->value  = value & 7;

  return true;
}

//----------------------------------------------------------------------
static bool S_ddddd(int value)
{
  if ( D_ddddd(value) )
  {
    op++;
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
static bool D_SR(int value)
{

        op->type = o_reg;
        op->dtyp = dt_word;
  op->reg  = uint16(SR0 + value);

        return true;
}

//----------------------------------------------------------------------
static bool S_SR(int value)
{
  if ( D_SR(value) )
  {
    op++;
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
static bool D_Imm(int value)
{
  op->type = o_imm;
  op->dtyp = dt_word;
  op->value = value & 0xffff;
  return true;
}

//----------------------------------------------------------------------
static bool D_pImm(int value)
{

  if ( value & 0x10 )
          D_Imm((value & 0x0f) << 4);
  else
          D_Imm(value & 0x0f);

  return true;
}

//----------------------------------------------------------------------
static bool D_EA(int value)
{
        op->addr = value;
        make_o_mem();
        return true;
}

//----------------------------------------------------------------------
static opcode table[] =
{

        {KR1878_mov,     "000001sssssddddd", {{S_ddddd, 0x1f}, {D_ddddd, 0x3e0}}  },
        {KR1878_cmp,     "000010sssssddddd", {{S_ddddd, 0x1f}, {D_ddddd, 0x3e0}}  },
        {KR1878_add,     "000100sssssddddd", {{S_ddddd, 0x1f}, {D_ddddd, 0x3e0}}  },
        {KR1878_sub,     "000011sssssddddd", {{S_ddddd, 0x1f}, {D_ddddd, 0x3e0}}  },
        {KR1878_and,     "000101sssssddddd", {{S_ddddd, 0x1f}, {D_ddddd, 0x3e0}}  },
        {KR1878_or,      "000110sssssddddd", {{S_ddddd, 0x1f}, {D_ddddd, 0x3e0}}  },
        {KR1878_xor,     "000111sssssddddd", {{S_ddddd, 0x1f}, {D_ddddd, 0x3e0}}  },
        {KR1878_movl,    "010ccccccccddddd", {{S_ddddd, 0x1f}, {D_Imm,   0x1fe0}} },
        {KR1878_cmpl,    "011ccccccccddddd", {{S_ddddd, 0x1f}, {D_Imm,   0x1fe0}} },
        {KR1878_addl,    "001100cccccddddd", {{S_ddddd, 0x1f}, {D_Imm,   0x3e0}}  },
        {KR1878_subl,    "001011cccccddddd", {{S_ddddd, 0x1f}, {D_Imm,   0x3e0}}  },
        {KR1878_bic,     "001010pccccddddd", {{S_ddddd, 0x1f}, {D_pImm,  0x3e0}}  },
        {KR1878_bis,     "001110pccccddddd", {{S_ddddd, 0x1f}, {D_pImm,  0x3e0}}  },
        {KR1878_btg,     "001111pccccddddd", {{S_ddddd, 0x1f}, {D_pImm,  0x3e0}}  },
        {KR1878_btt,     "001101pccccddddd", {{S_ddddd, 0x1f}, {D_pImm,  0x3e0}}  },
        {KR1878_swap,    "00000000001ddddd", {{D_ddddd, 0x1f}} },
        {KR1878_neg,     "00000000010ddddd", {{D_ddddd, 0x1f}} },
        {KR1878_not,     "00000000011ddddd", {{D_ddddd, 0x1f}} },
        {KR1878_shl,     "00000000100ddddd", {{D_ddddd, 0x1f}} },
        {KR1878_shr,     "00000000101ddddd", {{D_ddddd, 0x1f}} },
        {KR1878_shra,    "00000000110ddddd", {{D_ddddd, 0x1f}} },
        {KR1878_rlc,     "00000000111ddddd", {{D_ddddd, 0x1f}} },
        {KR1878_rrc,     "00000001000ddddd", {{D_ddddd, 0x1f}} },
        {KR1878_adc,     "00000001001ddddd", {{D_ddddd, 0x1f}} },
        {KR1878_sbc,     "00000001010ddddd", {{D_ddddd, 0x1f}} },
        {KR1878_ldr,     "00100ccccccccnnn", {{S_SR,    0x07}, {D_Imm,   0x07f8}} },
        {KR1878_mtpr,    "00000010nnnsssss", {{S_ddddd, 0x1f}, {D_SR,    0xe0  }} },
        {KR1878_mfpr,    "00000011nnnddddd", {{S_SR,    0xe0}, {D_ddddd, 0x1f  }} },
        {KR1878_push,    "0000000000010nnn", {{D_SR,    0x07}} },
        {KR1878_pop,     "0000000000011nnn", {{D_SR,    0x07}} },
        {KR1878_sst,     "000000011000bbbb", {{D_Imm,   0x0f}} },
        {KR1878_cst,     "000000011100bbbb", {{D_Imm,   0x0f}} },
        {KR1878_tof,     "0000000000000100"},
        {KR1878_tdc,     "0000000000000101"},
        {KR1878_jmp,     "100000aaaaaaaaaa", {{D_EA,    0x3ff}} },
        {KR1878_jsr,     "100100aaaaaaaaaa", {{D_EA,    0x3ff}} },
        {KR1878_jnz,     "101100aaaaaaaaaa", {{D_EA,    0x3ff}} },
        {KR1878_jz,      "101000aaaaaaaaaa", {{D_EA,    0x3ff}} },
        {KR1878_jns,     "110000aaaaaaaaaa", {{D_EA,    0x3ff}} },
        {KR1878_js,      "110100aaaaaaaaaa", {{D_EA,    0x3ff}} },
        {KR1878_jnc,     "111000aaaaaaaaaa", {{D_EA,    0x3ff}} },
        {KR1878_jc,      "111100aaaaaaaaaa", {{D_EA,    0x3ff}} },
        {KR1878_ijmp,    "0000000000000011"},
        {KR1878_ijsr,    "0000000000000111"},
        {KR1878_rts,     "0000000000001100"},
        {KR1878_rtsc,    "000000000000111c", {{D_Imm,   0x01}}  },
        {KR1878_rti,     "0000000000001101"},
        {KR1878_nop,     "0000000000000000"},
        {KR1878_wait,    "0000000000000001"},
        {KR1878_stop,    "0000000000001000"},
        {KR1878_reset,   "0000000000000010"},
        {KR1878_sksp,    "0000000000000110"},

};


//----------------------------------------------------------------------
static void make_masks(void)
{
  int i, j, b;

  for(i = 0; i < sizeof(table)/ sizeof(struct opcode); i++)
  {
    for(b = 0; b < strlen(table[i].recog); b++)
    {
      table[i].value <<= 1;
      table[i].mask <<= 1;

      if ( table[i].recog[b] == '1' || table[i].recog[b] == '0' )
        table[i].mask++;

      if ( table[i].recog[b] == '1' )
        table[i].value++;
    }

    for(j = 0; j < FUNCS_COUNT; j++)
    {
      if ( table[i].funcs[j].func )
      {
        for(b = 0; b < 16; b++)
        {
          if ( table[i].funcs[j].mask & (1 << b) )
            break;
          else
            table[i].funcs[j].shift++;
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
static bool use_table(uint32 code, int entry, int start, int end)
{
  opcode &ptr = table[entry];
  for(int j = start; j <= end; j++)
  {
    if ( !ptr.funcs[j].func ) break;
    int value = code & ptr.funcs[j].mask;
    value   >>=        ptr.funcs[j].shift;
    if ( !ptr.funcs[j].func(value) )
      return false;
  }
  return true;
}

//----------------------------------------------------------------------
int idaapi ana(void)
{
  uint code = ua_16bits();
  op = &cmd.Op1;

  for ( int i = 0; i < qnumber(table); i++ )
  {
    if ( (code & table[i].mask) == table[i].value )
    {
         cmd.itype = table[i].itype;
         cmd.size = 1;

         if ( !use_table(code, i, 0, FUNCS_COUNT - 1) ) continue;

      return cmd.size;
    }
  }
  return 0;
}

//--------------------------------------------------------------------------
void interr(const char *module)
{
  const char *name = NULL;
  if ( cmd.itype < KR1878_last )
    name = Instructions[cmd.itype].name;
  else
    cmd.itype = KR1878_null;
  warning("%a(%s): internal error in %s", cmd.ea, name, module);
}
