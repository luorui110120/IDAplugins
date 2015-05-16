
#include "oakdsp.hpp"

#define FUNCS_COUNT 5

struct funcdesc_t
{
  bool (*func)(int, int);
  int mask;
  int param;
  int shift;
};

struct opcode
{
  const char *recog;
  ushort itype;
  funcdesc_t funcs[FUNCS_COUNT];
  uchar  cycles;     //Number of cycles
  uint32 mask;
  uint32 value;
};

static op_t *op;       // current operand

//----------------------------------------------------------------------
static uint32 ua_32bits(void)
{

  uint32 x =             ( (get_full_byte(cmd.ea)                ) & 0x0000FFFF )
                        |       ( (get_full_byte(cmd.ea+1) << 16) & 0xFFFF0000 );

/*
  uint32 x =             (   (get_full_byte(cmd.ea)   >> 8 ) & 0x000000FF )
                        | ( (get_full_byte(cmd.ea)   << 8 ) & 0x0000FF00 )
                        | ( (get_full_byte(cmd.ea+1) << 8 ) & 0x00FF0000 )
                        | ( (get_full_byte(cmd.ea+1) << 24) & 0xFF000000 );

*/
  return x;
}


//----------------------------------------------------------------------
inline void opreg(int reg)
{
  op->type = o_reg;
  op->reg  = uint16(reg);
}

//----------------------------------------------------------------------
static void make_o_mem(void)
{
  if ( !(op->amode & amode_x) ) switch ( cmd.itype )
  {

    case OAK_Dsp_callr:
    case OAK_Dsp_call:
    case OAK_Dsp_br_u:
    case OAK_Dsp_br:
    case OAK_Dsp_brr_u:
    case OAK_Dsp_brr:
    case OAK_Dsp_bkrep:

      op->type   = o_near;
      op->dtyp   = dt_code;
      return;
  }
  op->type = o_mem;
}

//----------------------------------------------------------------------
static bool rrrrr(int value,int param)
{
        uint idx;
        if ( param & mix_mode )
                param = (param & 0xff) + value;
        idx = (param ? param: value);

        if ( idx >= PAGE ) return false;
        opreg(idx);
        if ( op->reg == uchar(-1) ) return false;

        op++;

        return true;
}
//----------------------------------------------------------------------
static bool sdirect(int value,int)
{
        op->amode = amode_short;
        op->addr = value & 0x00ff;
        op->amode |= amode_x;

        make_o_mem();
        op++;

        return true;
}
//----------------------------------------------------------------------
static bool ldirect(int value,int)
{

        op->amode = amode_long;
        op->addr = value & 0xffff;
        cmd.size++;
        op->amode |= amode_x;

        make_o_mem();
        op++;

        return true;
}
//----------------------------------------------------------------------
static bool A(int value,int)
{
        return( rrrrr(value & 0x01, A0 + mix_mode) );
}
//----------------------------------------------------------------------
static bool B(int value,int)
{
        return( rrrrr(value & 0x01, B0 + mix_mode) );
}
//----------------------------------------------------------------------
static bool mmnnn(int value,int)
{
        if ( (value & 0x07) > 0x05 )
                return false;

        op->type   = o_phrase;
        op->reg = value & 0x07;
        op->phtype = (value & 0x0018) >> 3;
        op++;

        return true;
}
//----------------------------------------------------------------------
static bool nnn(int value,int)
{

        return( rrrrr(value & 0x07, R0 + mix_mode ) );

}
//----------------------------------------------------------------------
static bool ALU_ALM(int value,int param)
{
        if ( param && ((value == 0x04) || (value == 0x05))  )
                return false;


        cmd.itype = OAK_Dsp_or + ( value & (param ? 0x07 : 0x0f) );
        return true;
}
//----------------------------------------------------------------------
static bool ALB(int value,int)
{

        cmd.itype = OAK_Dsp_set + (value & 0x07);
        return true;
}
//----------------------------------------------------------------------
static bool MUL(int value,int param)
{
        if ( param && (value > 0x03) )
                return false;

        cmd.itype = OAK_Dsp_mpy + ((value & (param ? 0x03 : 0x07)) << (param ? 0x01 : 0x00));
        return true;
}
//----------------------------------------------------------------------
static bool MODA_B(int value,int param)
{
        if ( value == 0x07 )
                return false;


        cmd.itype = OAK_Dsp_shr + ( value & (param ? 0x07 : 0x0f) );
        return true;
}
//----------------------------------------------------------------------
static bool s_Imm(int value, int)
{
        op->type  = o_imm;
        op->value = value;

        switch ( cmd.itype )
        {
                case OAK_Dsp_mpyi:
                        op->amode |= amode_signed;
                        break;
        }

        op++;
        return true;
}
//----------------------------------------------------------------------
static bool s_ImmS(int value, int param)
{

        uint mask1;
        uint mask2 = 0;
        uint i;

        mask1 =  1 << ( param - 1 );

        for (i = 0; i < param; i++)
                mask2 |= (1 << i);

        op->type  = o_imm;
        op->value = (value & mask2);
        op->amode |= amode_signed;

        if ( value & mask1 )
                op->value =  - ((value^mask2) + 1);


        op++;
        return true;
}
//----------------------------------------------------------------------
static bool l_Imm(int value, int)
{
        op->type  = o_imm;
        op->value = value & 0xffff;
        cmd.size++;

        switch ( cmd.itype )
        {
                case OAK_Dsp_maa:
                case OAK_Dsp_mac:
                case OAK_Dsp_macus:
                case OAK_Dsp_mpy:
                case OAK_Dsp_msu:
                        op->amode |= amode_signed;
                        break;
        }

        op++;
        return true;
}
//----------------------------------------------------------------------
static bool rb_rel_short(int value, int)
{
        op->type   = o_local;
        op->phtype = 0; // "rb + #displ"
        op->amode |= amode_signed;

        value = (value & 0x7f);

        if ( value & 0x40 )
                value = - ((value^0x7f) + 1);

        op->addr = value;
        op->amode |= amode_x;

        op++;

        return true;
}
//----------------------------------------------------------------------
static bool rb_rel_long(int value, int)
{
        int16 tmp;

        cmd.size++;
        op->type   = o_local;
        op->phtype = 0; // "rb + #displ"
        op->amode |= amode_signed;
        tmp = (value & 0xffff);
        op->addr = tmp;
        op->amode |= amode_x;

        op++;

        return true;
}
//----------------------------------------------------------------------
static bool Cond(int value,int param)
{
        cmd.auxpref |= value & 0x0f;

        if ( (!param) && ((value & 0x0f) > 0x00) )
                 cmd.auxpref |= aux_comma_cc;

        return true;
}
//----------------------------------------------------------------------
static bool xe_xt(int value, int param)
{
        static const uchar regs[] = { cc_ge, cc_gt, cc_le, cc_lt };

        cmd.auxpref |= regs[(value & 0x01) + (param ? 2 : 0)];
        cmd.auxpref |= aux_comma_cc;

        return true;

}
//----------------------------------------------------------------------
static bool lim_xx(int value, int)
{

        static const uchar regs1[] = {A0, A0, A1, A1};
        static const uchar regs2[] = {uchar(-1), A1, A0, uchar(-1)};

        opreg(regs1[value & 0x03]);

        if ( regs2[value & 0x03] != uchar(-1) )
        {
                op++;
                opreg(regs2[value & 0x03]);
        }

        return true;
}
//----------------------------------------------------------------------
static bool rJ_rI(int value,int param)
{

        //jjiiwqq

        op->type   = o_phrase;
        op->reg = (param ? (value & 0x03) : ((value & 0x04) >> 2) + 4 );
        op->phtype = (param ? (value & 0x0018) >> 3 : (value & 0x0060) >> 5 );
        op++;

        op->type   = o_phrase;
        op->reg = (param ? ((value & 0x04) >> 2) + 4 : (value & 0x03) );
        op->phtype = (param ? (value & 0x0060) >> 5 : (value & 0x0018) >> 3 );
        op++;

        return true;

}
//----------------------------------------------------------------------
static bool rI(int value,int)
{
        //iiqq

        op->type   = o_phrase;
        op->reg = (value & 0x03);
        op->phtype = (value & 0x0c) >> 2;
        op++;

        return true;
}
//----------------------------------------------------------------------
static bool AB(int value,int)
{
        static uchar regs[] = {B0, B1, A0, A1};

        opreg(regs[value & 0x03]);
        op++;

        return true;
}
//----------------------------------------------------------------------
static bool ABLH(int value,int)
{
        static uchar regs[] = {B0L, B0H, B1L, B1H, A0L, A0H, A1L, A1H};

        opreg(regs[value & 0x07]);
        op++;

        return true;
}
//----------------------------------------------------------------------
static bool indir_reg(int value,int param)
{
        op->type   = o_phrase;
        op->reg = uint16(param + value);
        op->phtype = 4;
        op++;

        return true;
}
//----------------------------------------------------------------------
static bool laddr_pgm(int value,int)
{

        op->amode |= amode_p;
        op->addr = value & 0xffff;
        cmd.size++;

        make_o_mem();
        op++;

        return true;
}
//----------------------------------------------------------------------
static bool addr_rel_pgm(int value, int)
{
        value = (value & 0x7f);
        op->amode |= amode_p;

        if ( value & 0x40 ) {
                value = (value^0x7f) + 1;
                op->addr = cmd.ea + 1 - value;
        }
        else
                op->addr = cmd.ea + 1 + value;


        make_o_mem();
        return true;
}
//----------------------------------------------------------------------
static bool ext_XX(int value, int)
{
        return( rrrrr( (value & 0x01) + ((value & 0x04) >> 1), EXT0 + mix_mode) );
}
//----------------------------------------------------------------------
static bool context(int value,int)
{
        if ( value )
                cmd.auxpref |= aux_iret_context;
        return true;
}
//----------------------------------------------------------------------
static bool swap(int value,int)
{
        op->type   = o_textphrase;
        op->phrase = value & 0x0f;
        op->phtype = text_swap;
        return true;

}
//----------------------------------------------------------------------
static bool banke(int value,int)
{

        op->type   = o_textphrase;
        op->phrase = value & 0x0f;
        op->phtype = text_banke;
        return true;
}
//----------------------------------------------------------------------
static bool cntx(int value,int)
{

        op->type   = o_textphrase;
        op->phrase = (uint16)value;
        op->phtype = text_cntx;
        return true;
}
//----------------------------------------------------------------------
static bool dmod(int value,int)
{
        op->type   = o_textphrase;
        op->phrase = (uint16)value;
        op->phtype = text_dmod;
        return true;
}
//----------------------------------------------------------------------
static bool eu(int,int)
{
        op->type   = o_textphrase;
        op->phtype = text_eu;
        return true;
}
//----------------------------------------------------------------------
static opcode table[]=
{

        {"0000000000000000", OAK_Dsp_nop,
#ifdef __BORLANDC__ // workaround of BCC5 bug
                                             {{}}
#else
                                             {{0}}
#endif
                                                  ,                                                                                                                     1 },
        {"0000000000100000", OAK_Dsp_trap,   {{0}},                                                                                                                     1 },
        {"0000000010fmmnnn", OAK_Dsp_modr,   {{mmnnn, 0x001f},                  {dmod, 0x0020}},                                                                        1 },
        {"0000000001arrrrr", OAK_Dsp_movp,   {{indir_reg, 0x20, A0},            {rrrrr, 0x001f}},                                                                       3 },
        {"000000010abrrrrr", OAK_Dsp_movs,   {{rrrrr, 0x001f},                  {AB, 0x0060}},                                                                          1 },
        {"000000011abmmnnn", OAK_Dsp_movs,   {{mmnnn, 0x001f},                  {AB, 0x0060}},                                                                          1 },
        {"00000100vvvvvvvv", OAK_Dsp_lpg,    {{s_Imm, 0x00ff}},                                                                                                         1 },
        {"00001000vvvvvvvv", OAK_Dsp_mpyi,   {{rrrrr, 0, Y},                    {s_Imm, 0x00ff}},                                                                       1 },
        {"00000101vvvvvvvv", OAK_Dsp_mov,    {{s_Imm, 0x00ff},                  {rrrrr, 0, SV}},                                                                        1 },
        {"00001001vvvvvvvv", OAK_Dsp_rets,   {{s_Imm, 0x00ff}},                                                                                                         3 },
        {"00001101---rrrrr", OAK_Dsp_rep,    {{rrrrr, 0x001f}},                                                                                                         1 },
        {"00001100vvvvvvvv", OAK_Dsp_rep,    {{s_Imm, 0x00ff}},                                                                                                         1 },
        {"0000011iiqqmmnnn", OAK_Dsp_movp,   {{mmnnn, 0x001f},                  {rI, 0x01e0}},                                                                          3 },
        {"0000111adddddddd", OAK_Dsp_divs,   {{sdirect, 0x00ff},                {A, 0x0100}},                                                                           1 },
        {"0000x01vvvvvvvvv", OAK_Dsp_load,   {{s_Imm, 0x01ff},                  {rrrrr, 0x0800, MODI|mix_mode}},                                                        1 },
        {"000110rrrrrmmnnn", OAK_Dsp_mov,    {{rrrrr, 0x03e0},                  {mmnnn, 0x001f}},                                                                       1 },
        {"000111rrrrrmmnnn", OAK_Dsp_mov,    {{mmnnn, 0x001f},                  {rrrrr, 0x03e0}},                                                                       1 },
        {"00010ooooooocccc", OAK_Dsp_callr,  {{addr_rel_pgm, 0x07f0},           {Cond, 0x000f}},                                                                        2 },
        {"0010nnn0dddddddd", OAK_Dsp_mov,    {{nnn, 0x0e00},                    {sdirect, 0x00ff}},                                                                     1 },
        {"001a0001vvvvvvvv", OAK_Dsp_mov,    {{s_Imm, 0x00ff},                  {rrrrr, 0x1000, A0L|mix_mode}},                                                         1 },
        {"001a0101vvvvvvvv", OAK_Dsp_mov,    {{s_Imm, 0x00ff},                  {rrrrr, 0x1000, A0H|mix_mode}},                                                         1 },
        {"001nnn11vvvvvvvv", OAK_Dsp_mov,    {{s_Imm, 0x00ff},                  {nnn, 0x1c00}},                                                                         1 },
        {"001x1x01vvvvvvvv", OAK_Dsp_mov,    {{s_Imm, 0x00ff},                  {ext_XX, 0x1400}},                                                                      1 },
        {"0011ABL0dddddddd", OAK_Dsp_mov,    {{ABLH, 0x0e00},                   {sdirect, 0x00ff}},                                                                     1 },
        {"0100001110000000", OAK_Dsp_eint,   {{0}},                                                                                                                     1 },
        {"0100001111000000", OAK_Dsp_dint,   {{0}},                                                                                                                     1 },
        {"0100000110000000", OAK_Dsp_br_u,   {{laddr_pgm, 0xffff0000}},                                                                                                 2 },
        {"0100010110000000", OAK_Dsp_ret_u,  {{0}},                                                                                                                     2 },
        {"01001101100000vv", OAK_Dsp_load,   {{s_Imm, 0x0003},                  {rrrrr, 0, PS}},                                                                        1 },
        {"01000101110f0000", OAK_Dsp_reti_u, {{context, 0x0010}},                                                                                                       2 },
        {"010001011000cccc", OAK_Dsp_ret,    {{Cond, 0x000f, 1}},                                                                                                       2 },
        {"010000011000cccc", OAK_Dsp_br,     {{laddr_pgm, 0xffff0000},          {Cond, 0x000f}},                                                                        2 },
        {"010000011100cccc", OAK_Dsp_call,   {{laddr_pgm, 0xffff0000},          {Cond, 0x000f}},                                                                        2 },
        {"01000111110rrrrr", OAK_Dsp_mov,    {{rrrrr, 0, MIXP},                 {rrrrr, 0x001f}},                                                                       1 },
        {"01000111111rrrrr", OAK_Dsp_mov,    {{indir_reg, 0, SP},               {rrrrr, 0x001f}},                                                                       1 },
        {"01000101110fcccc", OAK_Dsp_reti,   {{Cond, 0x000f, 1},                {context, 0x0010}},                                                                     1 },
        {"0100100110--swap", OAK_Dsp_swap,   {{swap,  0x000f}},                                                                                                         1 },
        {"0100111111-rrrrr", OAK_Dsp_mov,    {{rrrrr, 0x001f},                  {rrrrr, 0, ICR}},                                                                       1 },
        {"0100111110-vvvvv", OAK_Dsp_mov,    {{s_Imm, 0x001f},                  {rrrrr, 0, ICR}},                                                                       1 },
        {"0100100111xx----", OAK_Dsp_lim,    {{lim_xx, 0x0030}},                                                                                                        1 },
        {"010010111---bank", OAK_Dsp_banke,  {{banke, 0x000f}},                                                                                                         1 },
        {"0100nnn01abvvvvv", OAK_Dsp_movsi,  {{nnn, 0x0e00},                    {AB, 0x0060},                           {s_ImmS, 0x001f, 5}},                           1 },
        {"0100xxxa0ooooooo", OAK_Dsp_proc,   {{ALU_ALM, 0x0e00, 1},             {rb_rel_short, 0x007f},                 {A, 0x0100}},                                   1 },
        {"0101111101000000", OAK_Dsp_push,   {{l_Imm, 0xffff0000}},                                                                                                     2 },
        {"01011110010rrrrr", OAK_Dsp_push,   {{rrrrr, 0x001f}},                                                                                                         1 },
        {"01011110011rrrrr", OAK_Dsp_pop,    {{rrrrr, 0x001f}},                                                                                                         1 },
        {"01011110100rrrrr", OAK_Dsp_mov,    {{rrrrr, 0x001f},                  {rrrrr, 0, MIXP}},                                                                      1 },
        {"0101111011brrrrr", OAK_Dsp_mov,    {{rrrrr, 0x001f},                  {B, 0x0020}},                                                                           1 },
        {"01011101000rrrrr", OAK_Dsp_bkrep,  {{rrrrr, 0x001f},                  {laddr_pgm, 0xffff0000}},                                                               2 },
        {"0101111-000rrrrr", OAK_Dsp_mov,    {{l_Imm, 0xffff0000},              {rrrrr, 0x001f}},                                                                       2 },
        {"0101111b001-----", OAK_Dsp_mov,    {{l_Imm, 0xffff0000},              {B, 0x0100}},                                                                           2 },
        {"010111111jjiiwqq", OAK_Dsp_movd,   {{rJ_rI, 0x007f, 1}},                                                                                                      4 },
        {"01011100vvvvvvvv", OAK_Dsp_bkrep,  {{s_Imm, 0x00ff},                  {laddr_pgm, 0xffff0000}},                                                               2 },
        {"010110RRRRRrrrrr", OAK_Dsp_mov,    {{rrrrr, 0x001f},                  {rrrrr, 0x03e0}},                                                                       1 },
        {"01010ooooooo0000", OAK_Dsp_brr_u,  {{addr_rel_pgm, 0x07f0}},                                                                                                  2 },
        {"01010ooooooocccc", OAK_Dsp_brr,    {{addr_rel_pgm, 0x07f0},           {Cond, 0x000f}},                                                                        2 },
        {"01101101dddddddd", OAK_Dsp_mov,    {{sdirect, 0x00ff},                {rrrrr, 0, SV}},                                                                        1 },
        {"011nnn00dddddddd", OAK_Dsp_mov,    {{sdirect, 0x00ff},                {nnn, 0x1c00}},                                                                         1 },
        {"011AB001dddddddd", OAK_Dsp_mov,    {{sdirect, 0x00ff},                {AB, 0x1800}},                                                                          1 },
        {"011ABL10dddddddd", OAK_Dsp_mov,    {{sdirect, 0x00ff},                {ABLH, 0x1c00}},                                                                        1 },
        {"011A0101dddddddd", OAK_Dsp_mov_eu, {{sdirect, 0x00ff},                {A, 0x1000},                            {eu, 0x0}},                                     1 },
        {"011ab011dddddddd", OAK_Dsp_movs,   {{sdirect, 0x00ff},                {AB, 0x1800}},                                                                          1 },
        {"011b11110fffcccc", OAK_Dsp_proc,   {{MODA_B, 0x0070, 1},              {B, 0x1000},                            {Cond, 0x000f}},                                1 },
        {"011a0111ffffcccc", OAK_Dsp_proc,   {{MODA_B, 0x00f0},                 {A, 0x1000},                            {Cond, 0x000f}},                                1 },
        {"01111101dddddddd", OAK_Dsp_mov,    {{rrrrr, 0, SV},                   {sdirect, 0x00ff}},                                                                     1 },
        {"100000fa011mm000", OAK_Dsp_maxd,   {{A, 0x0100},                      {mmnnn, 0x001f},                        {xe_xt, 0x0200, 0}},                            1 },
        {"100001fa011mm000", OAK_Dsp_max,    {{A, 0x0100},                      {mmnnn, 0x001f},                        {xe_xt, 0x0200, 0}},                            1 },
        {"10001-fa011mm000", OAK_Dsp_min,    {{A, 0x0100},                      {mmnnn, 0x001f},                        {xe_xt, 0x0200, 1}},                            1 },
        {"1000xxxa11000000", OAK_Dsp_proc,   {{ALU_ALM, 0x0e00, 1},             {l_Imm, 0xffff0000},                    {A, 0x0100}},                                   2 },
        {"1000xxx0111mmnnn", OAK_Dsp_proc,   {{ALB, 0x0e00},                    {l_Imm, 0xffff0000},                    {mmnnn, 0x001f}},                               2 },
        {"1000xxx1111rrrrr", OAK_Dsp_proc,   {{ALB, 0x0e00},                    {l_Imm, 0xffff0000},                    {rrrrr, 0x001f}},                               2 },
        {"1000-00x001mmnnn", OAK_Dsp_proc,   {{MUL, 0x0700},                    {rrrrr, 0, Y},                          {mmnnn, 0x001f}},                               1 },
        {"1000axxx001mmnnn", OAK_Dsp_proc,   {{MUL, 0x0700},                    {rrrrr, 0, Y},                          {mmnnn, 0x001f},        {A, 0x0800}},           1 },
        {"1000-00x010rrrrr", OAK_Dsp_proc,   {{MUL, 0x0700},                    {rrrrr, 0, Y},                          {rrrrr, 0x001f}},                               1 },
        {"1000axxx010rrrrr", OAK_Dsp_proc,   {{MUL, 0x0700},                    {rrrrr, 0, Y},                          {rrrrr, 0x001f},        {A, 0x0800}},           1 },
        {"1000-00x000mmnnn", OAK_Dsp_proc,   {{MUL, 0x0700},                    {mmnnn, 0x001f},                        {l_Imm, 0xffff0000}},                           2 },
        {"1000axxx000mmnnn", OAK_Dsp_proc,   {{MUL, 0x0700},                    {mmnnn, 0x001f},                        {l_Imm, 0xffff0000},    {A, 0x0800}},           2 },
        {"100xxxxa100mmnnn", OAK_Dsp_proc,   {{ALU_ALM, 0x1e00},                {mmnnn, 0x001f},                        {A, 0x0100}},                                   1 },
        {"100xxxxa101rrrrr", OAK_Dsp_proc,   {{ALU_ALM, 0x1e00},                {rrrrr, 0x001f},                        {A, 0x0100}},                                   1 },
        {"1001000a110mmnnn", OAK_Dsp_msu,    {{mmnnn, 0x001f},                  {l_Imm, 0xffff0000},                    {A, 0x0100}},                                   2 },
        {"1001010a110mmnnn", OAK_Dsp_norm,   {{A, 0x0100},                      {mmnnn, 0x001f}},                                                                       2 },
        {"1001bbbb001mmnnn", OAK_Dsp_tstb,   {{s_Imm, 0x0f00},                  {mmnnn, 0x001f}},                                                                       1 },
        {"1001bbbb000rrrrr", OAK_Dsp_tstb,   {{s_Imm, 0x0f00},                  {rrrrr, 0x001f}},                                                                       1 },
        {"1001ab1AB1vvvvvv", OAK_Dsp_shfi,   {{AB, 0x0c00},                     {AB, 0x0180},                           {s_ImmS, 0x003f, 6}},                           1 },
        {"1001100a010mmnnn", OAK_Dsp_exp,    {{mmnnn, 0x001f},                  {A, 0x0100}},                                                                           1 },
        {"1001000a010rrrrr", OAK_Dsp_exp,    {{rrrrr, 0x001f},                  {A, 0x0100}},                                                                           1 },
        {"1001000a0110000b", OAK_Dsp_exp,    {{B, 0x0001},                      {A, 0x0100}},                                                                           1 },
        {"10011100010mmnnn", OAK_Dsp_exp,    {{mmnnn, 0x001f},                  {rrrrr, 0, SV}},                                                                        1 },
        {"10010100010rrrrr", OAK_Dsp_exp,    {{rrrrr, 0x001f},                  {rrrrr, 0, SV}},                                                                        1 },
        {"100101000110000b", OAK_Dsp_exp,    {{B, 0x0001},                      {rrrrr, 0, SV}},                                                                        1 },
        {"1001100b110mmnnn", OAK_Dsp_mov,    {{mmnnn, 0x001f},                  {B, 0x0100}},                                                                           1 },
        {"1001110a110rrrrr", OAK_Dsp_movr,   {{rrrrr, 0x001f},                  {A, 0x0100}},                                                                           1 },
        {"1001110a111mmnnn", OAK_Dsp_movr,   {{mmnnn, 0x001f},                  {A, 0x0100}},                                                                           1 },
        {"101xxxxadddddddd", OAK_Dsp_proc,   {{ALU_ALM, 0x1e00},                {sdirect, 0x00ff},                      {A, 0x0100}},                                   1 },
        {"1100xxxavvvvvvvv", OAK_Dsp_proc,   {{ALU_ALM, 0x0e00, 1},             {s_Imm, 0x00ff},                        {A, 0x0100}},                                   1 },
        {"1101001111000000", OAK_Dsp_break,  {{0}},                                                                                                                     1 },
        {"1101011110000000", OAK_Dsp_retd,   {{0}},                                                                                                                     1 },
        {"1101011111000000", OAK_Dsp_retid,  {{0}},                                                                                                                     1 },
        {"1101010a10000000", OAK_Dsp_calla,  {{A, 0x0100}},                                                                                                             3 },
        {"11010011100f0000", OAK_Dsp_cntx,   {{cntx, 0x0010}},                                                                                                          1 },
        {"110101001ab10000", OAK_Dsp_mov,    {{rrrrr, 0,REPC},                  {AB, 0x0060}},                                                                          1 },
        {"110101001ab10001", OAK_Dsp_mov,    {{rrrrr, 0,DVM},                   {AB, 0x0060}},                                                                          1 },
        {"110101001ab10010", OAK_Dsp_mov,    {{rrrrr, 0,ICR},                   {AB, 0x0060}},                                                                          1 },
        {"110101001ab10011", OAK_Dsp_mov,    {{rrrrr, 0,X},                     {AB, 0x0060}},                                                                          1 },
        {"1101010a101110--", OAK_Dsp_mov,    {{ldirect, 0xffff0000},            {A, 0x0100}},                                                                           2 },
        {"1101010a101111--", OAK_Dsp_mov,    {{rrrrr, 0x0100, A0L|mix_mode},    {ldirect, 0xffff0000}},                                                                 2 },
        {"1101010a100110--", OAK_Dsp_mov,    {{rb_rel_long,0xffff0000},         {A, 0x0100}},                                                                           2 },
        {"1101010a100111--", OAK_Dsp_mov,    {{rrrrr, 0x0100, A0L|mix_mode},    {rb_rel_long,0xffff0000}},                                                              2 },
        {"1101010a11011xxx", OAK_Dsp_proc,   {{ALU_ALM, 0x0007, 1},             {rb_rel_long, 0xffff0000},              {A, 0x0100}},                                   2 },
        {"1101010a11111xxx", OAK_Dsp_proc,   {{ALU_ALM, 0x0007, 1},             {ldirect, 0xffff0000},                  {A, 0x0100}},                                   2 },
        {"1101AB1011011000", OAK_Dsp_mov,    {{AB, 0x0c00},                     {rrrrr, 0x0000, X}},                                                                    1 },
        {"1101AB1010011000", OAK_Dsp_mov,    {{AB, 0x0c00},                     {rrrrr, 0x0000, DVM}},                                                                  1 },
        {"1101ab101AB10000", OAK_Dsp_mov,    {{AB, 0x0c00},                     {AB, 0x0060}},                                                                          1 },
        {"1101000a1jjiiwqq", OAK_Dsp_msu,    {{rJ_rI, 0x007f},                  {A, 0x0100}},                                                                           1 },
        {"1101ab101AB0cccc", OAK_Dsp_shfc,   {{AB, 0x0c00},                     {AB, 0x0060},                           {Cond, 0x000f}},                                1 },
        {"1101100a1ooooooo", OAK_Dsp_mov,    {{rb_rel_short, 0x007f},           {A, 0x0100}},                                                                           1 },
        {"1101110a1ooooooo", OAK_Dsp_mov,    {{rrrrr, 0x0100, A0L|mix_mode},    {rb_rel_short, 0x007f}},                                                                1 },
        {"11011x111vvvvvvv", OAK_Dsp_load,   {{s_Imm, 0x007f},                  {rrrrr, 0x0400, STEPI|mix_mode}},                                                       1 },
        {"1101-00x0jjiiwqq", OAK_Dsp_proc,   {{MUL, 0x0700},                    {rJ_rI, 0x007f}},                                                                       1 },
        {"1101axxx0jjiiwqq", OAK_Dsp_proc,   {{MUL, 0x0700},                    {rJ_rI, 0x007f},                        {A, 0x0800}},                                   1 },
        {"1110xxx1dddddddd", OAK_Dsp_proc,   {{ALB, 0x0e00},                    {l_Imm, 0xffff0000},                    {sdirect, 0x00ff}},                             2 },
        {"1110-000dddddddd", OAK_Dsp_proc,   {{MUL, 0x0600, 1},                 {rrrrr, 0, Y},                          {sdirect, 0x00ff}},                             1 },
        {"1110axx0dddddddd", OAK_Dsp_proc,   {{MUL, 0x0600, 1},                 {rrrrr, 0, Y},                          {sdirect, 0x00ff},      {A, 0x0800}},           1 },
        {"1111bbbbdddddddd", OAK_Dsp_tstb,   {{s_Imm, 0x0f00},                  {sdirect, 0x00ff}},                                                                     1 },

};

//----------------------------------------------------------------------
static void make_masks(opcode *table, int qty)
{
  int i, j, b;

  for(i = 0; i < qty; i++)
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
        for(b = 0; b < 32; b++)
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
  make_masks(table, qnumber(table));
}


//----------------------------------------------------------------------
static bool use_table(opcode *table, uint code, int entry, int start, int end)
{
  opcode &ptr = table[entry];
  for(int j = start; j <= end; j++)
  {
    if ( !ptr.funcs[j].func ) break;
    int value = (code & ptr.funcs[j].mask) >> ptr.funcs[j].shift;
    if ( !ptr.funcs[j].func(value, ptr.funcs[j].param) )
      return false;
  }
  return true;
}

//----------------------------------------------------------------------
static void reset_ops(void)
{
  op = &cmd.Op1;
  for ( int i=0; i < UA_MAXOP; i++ )
    cmd.Operands[i].type = o_void;
}

//----------------------------------------------------------------------
int idaapi ana(void)
{
  uint code = ua_32bits();
  uint prev_inst_code;
  op = &cmd.Op1;
  int16 tmp;
  int  move_rb_to_reg = 0;


  for ( int i = 0; i < qnumber(table); i++ )
  {
    if ( (code & table[i].mask) == table[i].value )
    {
      cmd.itype = table[i].itype;
      cmd.cmd_cycles = table[i].cycles;
      cmd.size = 1;

        if ( !use_table(table, code, i, 0, FUNCS_COUNT - 1) )
        {
          reset_ops();
          continue;
        }



        // mov #imm, pc --> near jump

        if ( ( cmd.itype == OAK_Dsp_mov ) && (cmd.Op1.type == o_imm) && (cmd.Op2.type == o_reg) && (cmd.Op2.reg == PC) )
        {
                cmd.Op1.type = o_near;
                cmd.Op1.dtyp = dt_code;
                cmd.Op1.addr = cmd.Op1.value;
                cmd.Op1.amode = amode_p;
        }


        // add(sub) #imm, reg  after  mov rb, reg instruction
        // #imm --> local var

        if ( (cmd.ea - 1) != BADADDR )
        {
                prev_inst_code = get_full_byte(cmd.ea - 1);

                if ( ((prev_inst_code & 0xfc1f) == 0x5806) || ((prev_inst_code & 0xffdf) == 0x5ec6) )
                {
                        if ( (prev_inst_code & 0xfc1f) == 0x5806 ) // mov reg, reg
                                move_rb_to_reg = (prev_inst_code >> 5) & 0x1f;
                        else
                                if ( (prev_inst_code & 0xffdf) == 0x5ec6 )       // mov reg, bx
                                        move_rb_to_reg =  B0 + ((prev_inst_code >> 5) & 0x01);

                        if ( (cmd.Op1.type == o_imm) && ( (cmd.Op2.reg == move_rb_to_reg) \
                        || ( (cmd.Op2.reg == A0L) && (move_rb_to_reg == A0) ) \
                        || ( (cmd.Op2.reg == A1L) && (move_rb_to_reg == A1) ) \
                        || ( (cmd.Op2.reg == B0L) && (move_rb_to_reg == B0) ) \
                        || ( (cmd.Op2.reg == B1L) && (move_rb_to_reg == B1) ) ) )
                        {

                                tmp = (int16)cmd.Op1.value;

                                switch ( cmd.itype )
                                {
                                        case OAK_Dsp_sub:
                                        case OAK_Dsp_subv:
                                                tmp = - tmp;
                                                //no break
                                        case OAK_Dsp_add:
                                        case OAK_Dsp_addv:
                                                cmd.Op1.addr =  tmp;
                                                cmd.Op1.type   = o_local;
                                                cmd.Op1.phtype = 1; // "#"
                                                cmd.Op1.amode |= amode_signed;
                                                cmd.Op1.amode |= amode_x;
                                                break;
                                }

                        }
                }
        }


        // add(sub) #imm, SP
        // #imm --> signed imm

        if ( (cmd.Op1.type == o_imm) && (cmd.Op2.type == o_reg) && (cmd.Op2.reg == SP) )
                switch ( cmd.itype )
                {
                        case OAK_Dsp_add:
                        case OAK_Dsp_addv:
                        case OAK_Dsp_sub:
                        case OAK_Dsp_subv:
                                cmd.Op1.amode |= amode_signed;
                                break;
                }


      return cmd.size;
    }
  }
  return 0;
}

//--------------------------------------------------------------------------
void interr(const char *module)
{
  const char *name = NULL;
  if ( cmd.itype < OAK_Dsp_last )
    name = Instructions[cmd.itype].name;
  else
    cmd.itype = OAK_Dsp_null;
  warning("%a(%s): internal error in %s", cmd.ea, name, module);
}
