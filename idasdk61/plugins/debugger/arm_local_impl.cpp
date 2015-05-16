#include <set>

#include <idp.hpp>
#include <dbg.hpp>
#include <srarea.hpp>
#include <segment.hpp>

#include "deb_arm.hpp"

//--------------------------------------------------------------------------
//
//      DEBUGGER REGISTER AND INSTRUCTIONS INFORMATIONS
//
//--------------------------------------------------------------------------

const char *arm_register_classes[] =
{
  "General registers",
//  "FPU registers",
  NULL
};


static const char *const psr[] =
{
  "MODE",       // 0
  "MODE",       // 1
  "MODE",       // 2
  "MODE",       // 3
  "MODE",       // 4
  "T",          // 5
  "F",          // 6
  "I",          // 7
  "A",          // 8
  "E",          // 9
  "IT",         // 10
  "IT",         // 11
  "IT",         // 12
  "IT",         // 13
  "IT",         // 14
  "IT",         // 15
  "GE",         // 16
  "GE",         // 17
  "GE",         // 18
  "GE",         // 19
  NULL,         // 20
  NULL,         // 21
  NULL,         // 22
  NULL,         // 23
  "J",          // 24
  "IT",         // 25
  "IT",         // 26
  "Q",          // 27
  "V",          // 28
  "C",          // 29
  "Z",          // 30
  "N",          // 31
};

register_info_t arm_registers[] =
{
  // FPU registers
//  { "VFP0",   0,                            ARM_RC_FPU,      dt_tbyte, NULL,   0 },
//  { "VFP1",   0,                            ARM_RC_FPU,      dt_tbyte, NULL,   0 },
//  { "VFP2",   0,                            ARM_RC_FPU,      dt_tbyte, NULL,   0 },
//  { "VFP3",   0,                            ARM_RC_FPU,      dt_tbyte, NULL,   0 },
//  { "VFP4",   0,                            ARM_RC_FPU,      dt_tbyte, NULL,   0 },
//  { "VFP5",   0,                            ARM_RC_FPU,      dt_tbyte, NULL,   0 },
//  { "VFP6",   0,                            ARM_RC_FPU,      dt_tbyte, NULL,   0 },
//  { "VFP7",   0,                            ARM_RC_FPU,      dt_tbyte, NULL,   0 },
//  { "SCR",    0,                            ARM_RC_FPU,      dt_word,  NULL,   0 },
//  { "EXC",    0,                            ARM_RC_FPU,      dt_word,  NULL,   0 },
  { "R0",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R1",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R2",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R3",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R4",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R5",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R6",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R7",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R8",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R9",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R10",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R11",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "R12",   REGISTER_ADDRESS|REGISTER_FP, ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "SP",    REGISTER_ADDRESS|REGISTER_SP, ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "LR",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "PC",    REGISTER_ADDRESS|REGISTER_IP, ARM_RC_GENERAL,  dt_dword, NULL,   0 },
  { "PSR",   0,                            ARM_RC_GENERAL,  dt_dword, psr,    0xF800007F },
};

//--------------------------------------------------------------------------
int idaapi arm_read_registers(thid_t thread_id, int clsmask, regval_t *values)
{
  return s_read_registers(thread_id, clsmask, values);
}

//--------------------------------------------------------------------------
int idaapi arm_write_register(thid_t thread_id, int regidx, const regval_t *value)
{
  return s_write_register(thread_id, regidx, value);
}

//--------------------------------------------------------------------------
int is_arm_valid_bpt(bpttype_t type, ea_t ea, int len)
{
  if ( type == BPT_SOFT )
  {
    if ( (ea & 1) != 0 )
      return BPT_BAD_ADDR;
  }
  else
  {
    if ( type != BPT_RDWR         // type is good?
      && type != BPT_WRITE
      && type != BPT_EXEC)
        return BPT_BAD_TYPE;

    if ( (ea & (len-1)) != 0 )    // alignment is good?
      return BPT_BAD_ALIGN;

    if ( len != 1 )
    {
      warning("AUTOHIDE REGISTRY\n"
              "xScale supports only 1 byte length hardware breakpoints");
      return BPT_BAD_LEN;
    }
  }
  return BPT_OK;
}

//--------------------------------------------------------------------------
// if bit0 is set, ensure that thumb mode
// if bit0 is clear, ensure that arm mode
static void handle_arm_thumb_modes(ea_t ea)
{
  bool should_be_thumb = (ea & 1) != 0;
  bool is_thumb = getSR(ea, ARM_T);
  if ( should_be_thumb != is_thumb )
  {
    int code = processor_t::loader + (should_be_thumb ? 0 : 1);
    ph.notify(processor_t::idp_notify(code), ea & ~1);
  }
}

//--------------------------------------------------------------------------
typedef std::set<ea_t> easet_t;
static easet_t pending_addresses;

static int idaapi dbg_callback(void *, int code, va_list)
{
  // we apply thumb/arm switches when the process is suspended.
  // it is quite late (normally we should do it as soon as the corresponding
  // segment is created) but i did not manage to make it work.
  // in the segm_added event the addresses are not enabled yet,
  // so switching modes fails.
  if ( code == dbg_suspend_process && !pending_addresses.empty() )
  {
    for ( easet_t::iterator p=pending_addresses.begin();
          p != pending_addresses.end();
          ++p )
    {
      handle_arm_thumb_modes(*p);
    }
    pending_addresses.clear();
  }
  return 0;
}

//--------------------------------------------------------------------------
// For ARM processors the low bit means 1-thumb, 0-arm mode.
// The following function goes over the address list and sets the mode
// in IDA database according to bit0. It also resets bit0 for all addresses.
void set_arm_thumb_modes(ea_t *addrs, int qty)
{
  for ( int i=0; i < qty; i++ )
  {
    ea_t ea = addrs[i];
    segment_t *s = getseg(ea);
    if ( s == NULL )
      pending_addresses.insert(ea);
    else
      handle_arm_thumb_modes(ea);

    addrs[i] = ea & ~1;
  }
}

//--------------------------------------------------------------------------
void processor_specific_init(void)
{
  hook_to_notification_point(HT_DBG, dbg_callback, NULL);
}

//--------------------------------------------------------------------------
void processor_specific_term(void)
{
  unhook_from_notification_point(HT_DBG, dbg_callback, NULL);
  pending_addresses.clear();
}
