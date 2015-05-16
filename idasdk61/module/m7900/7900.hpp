/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#ifndef _MITSUBISHI7900_HPP
#define _MITSUBISHI7900_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <srarea.hpp>

#define UAS_NOSPA        0x0001         // no space after comma
#define UAS_SEGM         0x0002         // segments are named "segment XXX"


// flags for cmd.auxpref
//Для указания какой префикс будет добавлен к операнду
// 0x1 - .b
// 0x2 - .w
// 0x4 - .d

#define INSN_PREF_U 0x0000
#define INSN_PREF_B 0x0001
#define INSN_PREF_W 0x0002
#define INSN_PREF_D 0x0004

#define RAZOPER cmd.auxpref

//Detect status value
#define getFlag_M getSR(cmd.ea, rfM)
#define getFlag_X getSR(cmd.ea, rfX)

#define getDT getSR(cmd.ea, rDT)
#define getPG getSR(cmd.ea, rPG)

#define getDPReg  getSR(cmd.ea, rDPReg)

#define getDPR0  getSR(cmd.ea, rDPR0)
#define getDPR1  getSR(cmd.ea, rDPR1)
#define getDPR2  getSR(cmd.ea, rDPR2)
#define getDPR3  getSR(cmd.ea, rDPR3)


//----------------------------------------------------------------------
// Redefine temporary names
//

#define         xmode       specflag1
#define         TypeOper    specflag2

#define         o_sr       o_idpspec0
#define         o_ab       o_idpspec1
#define         o_stk      o_idpspec2


//
//

enum mitsubishi_bit_PUL { bPS, bb, bDT, bDPR0, bY, bX, bB, bA };
// =======   mitsubishi_bit_CPU  ========================================
/*
 __________________________
|...   |IPL|N|V|m|x|D|I|Z|C|
 __________________________
*/

//
//      Bit 0: Carry flag (C)
//      Bit 1: Zero flag (Z)
//      Bit 2: Interrupt disable flag (I)
//      Bit 3: Decimal mode flag (D)
//      Bit 4: Index register length flag (x)
//      Bit 5: Data length flag (m)
//      Bit 6: Overflow flag (V)
//      Bit 7: Negative flag (N)
//      Bits 10 to 8: Processor interrupt priority level (IPL)
//
enum mitsubishi_bit_CPU { bIPL, bN, bV, bm, bx, bD, bI, bZ, bC };


enum mitsubishi_registers { rA, rB, rE, rX, rY, rPC,
                            rPS,
                            rfIPL, rfN, rfV, rfD, rfI, rfZ, rfC,
                            rDT, rPG, rDPReg, rDPR0, rDPR1, rDPR2, rDPR3,rfM, rfX,
                            Rcs, Rds };




/*
                      15____________________0
                       |    Ah   |   AL      | - Accumulator A
                        _____________________
15____________________0
|    Bh   |   BL      |                         - Accumulator B
| ____________________|

31___________________________________________0
|        Eh           |        EL            | - Accumulator E
 _____________________________________________

15____________________0
|    Xh   |   XL      |                         - Index registr X
 _____________________
15____________________0
|    Yh   |   YL      |                         - Index registr Y
 _____________________

15____________________0
|    Sh   |   SL      |                         - Stack pointer S
 _____________________

8_________0
|    DT   |                                     - Data bank registr(DT)
 _________

23_________15___________________0
|    PG   |    PCh   |   PCl    |                         - Program counter(PC)
 _______________________________
   |_____________________________________________________ - Program bank registr()PG

15____________________0
| DPR0h  | DPR0L     |                         - Direct page registr 0(DPR0)
 _____________________
15____________________0
| DPR1h  | DPR1L     |                         - Direct page registr 1(DPR1)
 _____________________
15____________________0
| DPR2h  | DPR2L     |                         - Direct page registr 2(DPR2)
 _____________________
15____________________0
| DPR3h  | DPR3L     |                         - Direct page registr 3(DPR3)
 _____________________
15____________________0
|  PSh     | PS L     |                         - Procesor status register(PS)
 _____________________
*/





enum eMode{ IMM_8=0, IMM_16, IMM_32, DIR_32, DIR_16, DIR_8 };


// TDIR_DIR       - Direct addressing mode DIR
// TDIR_DIR_X     - Direct index X addressing DIR,X
// TDIR_DIR_Y     -  Direct index Y addressing DIR,Y
// TDIR_INDIRECT_DIR     - Direct indirect addressing mode (DIR)
// TDIR_INDIRECT_DIR_X   - Direct index X indirect addressing mode (DIR,X)
// TDIR_INDIRECT_DIR_Y   - Direct index Y indirect addressing mode (DIR,Y)
// TDIR_L_INDIRECT_DIR   - Direct indirect long addressing mode L(DIR)
// TDIR_L_INDIRECT_DIR_Y - Direct indirect long indexed Y addressing mode L(DIR),Y

enum eTypeDIR{ TDIR_DIR=0, TDIR_DIR_X, TDIR_DIR_Y, TDIR_INDIRECT_DIR,
               TDIR_INDIRECT_DIR_X, TDIR_INDIRECT_DIR_Y, TDIR_L_INDIRECT_DIR, TDIR_L_INDIRECT_DIR_Y };


// TSP_SP         - Stack pointer relative addressing mode(SR)
// TSP_INDEX_SP_Y - Stack pointer relative indexed Y addressing mode((SR),Y)

enum eTypeSP{TSP_SP=0, TSP_INDEX_SP_Y };


// TAB_ABS    - Absolute addressing mode(ABS)
// TAB_ABS_X  - Absolute indexed X addressing mode(ABS,X)
// TAB_ABS_Y  - Absolute indexed Y addressing mode(ABS,Y)
// TAB_ABL    - Absolute long addressing mode(ABL)
// TAB_ABL_X - Absolute long indexed X addressing mode(ABS,X)
// TAB_INDIRECTED_ABS - Absolute indirect addressing mode((ABS))
// TAB_L_INDIRECTED_ABS - Absolute indirect long addressing mode(L(ABS))
// TAB_INDIRECTED_ABS_X - Absolute indexed X indirect addressing mode((ABS,X))

enum eTypeAB{ TAB_ABS=0, TAB_ABS_X, TAB_ABS_Y, TAB_ABL, TAB_ABL_X,
              TAB_INDIRECTED_ABS, TAB_L_INDIRECTED_ABS, TAB_INDIRECTED_ABS_X };


//------------------------------------------------------------------------
extern char device[];
extern char deviceparams[];

struct ioport_bit_t;
bool mitsubishi_find_ioport_bit(int port, int bit);
//------------------------------------------------------------------------
void    idaapi header(void);
void    idaapi footer(void);

void    idaapi gen_segm_header(ea_t ea);

int     idaapi ana(void);
int     idaapi emu(void);
void    idaapi out(void);
bool    idaapi outop(op_t &op);


inline void TRACE1(const char *szStr)
{
  msg("%s\n", szStr);
}


inline void TRACE1(uint32 Data)
{
  msg("DATA - %X\n", Data);
}


inline void TRACE(const char * /*szStr*/)
{
//  msg("%s\n", szStr);
}


inline void TRACE(uint32 /*Data*/)
{
//  msg("DATA - %X\n", Data);
}

inline int GETBIT(uval_t Data, int bit)
{
 uint32 TempByte = (uint32)Data;
 return (((TempByte>>bit)&0x01));
}

#endif

