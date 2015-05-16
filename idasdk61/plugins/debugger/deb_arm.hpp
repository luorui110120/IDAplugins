#ifndef __DEB_ARM__
#define __DEB_ARM__

#include <ua.hpp>
#include <idd.hpp>

#if DEBUGGER_ID != DEBUGGER_ID_GDB_USER
#define Eip Pc
#define Esp Sp
typedef uint32 cpuregtype_t;
#endif

#define MEMORY_PAGE_SIZE 0x1000
//FIXME: #if DEBUGGER_ID == DEBUGGER_ID_ARM_WINCE_USER
// (The preprocessor defines are not propagated properly)
#ifdef UNDER_CE
#  define ARM_BPT_CODE    { 0x10, 0x00, 0x00, 0xE6 }    // wince bkpt
#else
#  define ARM_BPT_CODE    { 0xF0, 0x01, 0xF0, 0xE7 }    // und #10
//#  define ARM_BPT_CODE    { 0xFE, 0xDE, 0xFF, 0xE7 }    // illegal opcode
//#  define ARM_BPT_CODE    { 0x70, 0x00, 0x20, 0xE1 }    // bkpt
#endif

#define FPU_REGS_COUNT  8       // number of FPU registers
#define ARM_BPT_SIZE 4         // size of BPT instruction

#define ARM_T 20                // number of virtual T segment register in IDA
                                // it controls thumb/arm mode.

enum register_class_arm_t
{
  ARM_RC_GENERAL          = 0x01,
//  RC_FPU              = 0x02,
  ARM_RC_ALL = ARM_RC_GENERAL,
};

// parallel arrays, must be edited together: arm_debmod_t::get_regidx()
//                                           register_info_t arm_registers[]
enum register_arm_t
{
/*
  // FPU registers
  R_VFP0,
  R_VFP1,
  R_VFP2,
  R_VFP3,
  R_VFP4,
  R_VFP5,
  R_VFP6,
  R_VFP7,
  R_SCR,
  R_EXC, */
  // general registers
  R_R0,
  R_R1,
  R_R2,
  R_R3,
  R_R4,
  R_R5,
  R_R6,
  R_R7,
  R_R8,
  R_R9,
  R_R10,
  R_R11,
  R_R12,
  R_SP,
  R_LR,
  R_PC,
  R_PSR,
};

extern const char *arm_register_classes[];
extern register_info_t arm_registers[17];
int idaapi arm_read_registers(thid_t thread_id, int clsmask, regval_t *values);
int idaapi arm_write_register(thid_t thread_id, int reg_idx, const regval_t *value);
int is_arm_valid_bpt(bpttype_t type, ea_t ea, int len);

#endif

