/*
   Metrowerks TRK interface.
*/

#ifndef METROTRK_H
#define METROTRK_H

// Frame level
#define FRAME_FLAG    0x7e  // Frame start/end mark
#define FRAME_ESCAPE  0x7d  // Escape
#define FRAME_TRANS   0x20  // XOR with this value
#define MAX_FRAME_DATA 256 // 0x800 // Maximum frame data size

// Packet level
enum trk_message_code_t
{
  TrkPing               = 0x00,
  TrkConnect            = 0x01,
  TrkDisconnect         = 0x02,
  TrkReset              = 0x03,
  TrkVersions           = 0x04,
  TrkSupportMask        = 0x05,
  TrkCPUType            = 0x06,
  TrkReadMemory         = 0x10,
  TrkWriteMemory        = 0x11,
  TrkReadRegisters      = 0x12,
  TrkWriteRegisters     = 0x13,
  TrkFillMemory         = 0x14,
  TrkCopyMemory         = 0x15,
  TrkFlushCache         = 0x16,
  TrkContinue           = 0x18,
  TrkStep               = 0x19,
  TrkStop               = 0x1a,
  TrkSetBreak           = 0x1b,
  TrkClearBreak         = 0x1c,
  TrkModifyBreakThread  = 0x1e,
  TrkOSCreateItem       = 0x40,
  TrkOSDeleteItem       = 0x41,
  TrkOSReadInfo         = 0x42,
  TrkOSWriteInfo        = 0x43,
  TrkOSWriteFile        = 0x48,
  TrkOSReadFile         = 0x49,
  TrkOSOpenFile         = 0x4a,
  TrkOSCloseFile        = 0x4b,
  TrkOSPositionFile     = 0x4c,
  TrkOSInstallFile      = 0x4d,
  TrkReplyACK           = 0x80,
  TrkReplyNAK           = 0xFF,
  TrkNotifyStopped      = 0x90,
  TrkOSNotifyCreated    = 0xa0,
  TrkOSNotifyDeleted    = 0xa1,
  TrkWriteFile          = 0xD0,
  TrkReadFile           = 0xD1,
  TrkOpenFile           = 0xD2,
  TrkCloseFile          = 0xD3,
  TrkPositionFile       = 0xD4
};

enum trk_step_options_t
{
  TrkStepIntoRange = 0x01,
  TrkStepOverRange = 0x11
};

enum trk_os_item_type_t
{
  TrkOSProcessItem      = 0x0000,
  TrkOSThreadItem       = 0x0001,
  TrkOSDLLItem          = 0x0002,
  TrkOSAppItem          = 0x0003,
  TrkOSMemBlockItem     = 0x0004,
  TrkOSProcAttachItem   = 0x0005,
  TrkOSThreadAttachItem = 0x0006
};

enum trk_info_type_t
{
  TrkOSProcessList      = 0x0000,
  TrkOSProcessState     = 0x0001,
  TrkOSThreadList       = 0x0002,
  TrkOSThreadState      = 0x0003,
  TrkOSDLLList          = 0x0004,
  TrkOSDLLState         = 0x0005
};

typedef int trk_open_mode_t;
const trk_open_mode_t
  TrkFileOpenRead       = 0x01,
  TrkFileOpenWrite      = 0x02,
  TrkFileOpenAppend     = 0x04,
  TrkFileOpenBinary     = 0x08,
  TrkFileOpenCreate     = 0x10,
  TrkFileOpenExec       = 0x20;

enum trk_errors_t
{
  TrkReplyNoError              = 0x00,  // no error
  TrkReplyError                = 0x01,  // generic error in CWDS message
  TrkReplyPacketSizeError      = 0x02,  // unexpected pkt size in send msg
  TrkReplyCWDSError            = 0x03,  // internal error occurred in CWDS
  TrkReplyEscapeError          = 0x04,  // escape followed by frame flag
  TrkReplyBadFCS               = 0x05,  // bad FCS in packet
  TrkReplyOverflow             = 0x06,  // packet too long
  TrkReplySequenceMissing      = 0x07,  // sequence ID != expected (gap in sequence)
  TrkReplyUnsupportedCmd       = 0x10,  // command not supported
  TrkReplyParameterError       = 0x11,  // command param out of range
  TrkReplyUnsupportedOption    = 0x12,  // an option was not supported
  TrkReplyInvalidMemoryRange   = 0x13,  // read/write to invalid memory
  TrkReplyInvalidRegisterRange = 0x14,  // read/write invalid registers
  TrkReplyCWDSException        = 0x15,  // exception occurred in CWDS
  TrkReplyNotStopped           = 0x16,  // targeted system or thread is running
  TrkReplyBreakpointsFull      = 0x17,  // bp resources (HW or SW) exhausted
  TrkReplyBreakpointConflict   = 0x18,  // requested bp conflicts w/existing bp
  TrkReplyOsError              = 0x20,  // general OS-related error
  TrkReplyInvalidProcessId     = 0x21,  // request specified invalid process
  TrkReplyInvalidThreadId      = 0x22   // request specified invalid thread
};

//-------------------------------------------------------------------------
struct trk_cpuinfo_t
{
  uchar cpuMajor;
  uchar cpuMinor;
  uchar bigEndian;
  uchar defaultTypeSize;
  uchar fpTypeSize;
  uchar extended1TypeSize;
  uchar extended2TypeSize;
};

struct trk_process_info_t
{
  int32 pid;            // process id
  int32 tid;            // thread id
  int32 codeaddr;       // code address
  int32 dataaddr;       // data address
  trk_process_info_t(void) {}
  trk_process_info_t(int32 x) : pid(x) {}
};

struct proclist_entry_t
{
  int32 pid;
  int32 priority;
  qstring name;
};
typedef qvector<proclist_entry_t> proclist_t;

struct thread_list_entry_t
{
  int32 tid;
  int32 priority;
  qstring name;
  bool is_suspended;
};
typedef qvector<thread_list_entry_t> thread_list_t;

struct metrotrk_t
{
  HANDLE hp;
  COMMTIMEOUTS ct;
  bytevec_t pkt;
  qstack<bytevec_t> out_of_order;
                          // if a user cmd and a notification occur simultaneously
                          // trk will first send its notification and expect
                          // a response to it; however, it will send the response
                          // to the user command first and only after that
                          // it will acknowledge the notification reception.
                          // in other words:
                          //  user sends the first cmd to trk
                          //  trk responds with notification
                          //    user responds to the notification and sends second cmd
                          //    trk responds to the first user cmd
                          //  trk responds to the second user cmd
                          // the indented events happen in process_packet().
                          // so we need a means to store packets somewhere
  uchar checksum;
  int sseq;               // sequence id
  trk_process_info_t tpi; // running process info
  void *ud;               // user data
  bool recv_byte(uchar *byte);
  void init_packet(void) { pkt.qclear(); pkt.push_back(FRAME_FLAG); checksum = 0; }
  void init_packet(uchar type) { init_packet(); append_byte(type); append_byte((uchar)sseq++); }
  void append_byte(uchar byte);
  void append_int16(uint16 x);
  void append_int32(uint32 x);
  void append_data(const void *bytes, size_t len=0);
  void prepend_byte(uchar byte);
  void prepend_hdr(void);
  bool send_packet(void);
  bool process_packet(size_t minsize, bool allow_extra_bytes=false);
  ssize_t write_file_chunk(int h, const void *bytes, size_t size);
  ssize_t read_file_chunk(int h, void *bytes, size_t size);
  ssize_t read_memory_chunk(int pid, int tid, int32 addr, void *bytes, size_t size);
  ssize_t write_memory_chunk(int pid, int tid, int32 addr, const void *bytes, size_t size);
  bool handle_notification(uchar seq, void *ud);
  int set_timeout(int timeout_ms); // returns old timeout
public:
  metrotrk_t(void *_ud) : hp(INVALID_HANDLE_VALUE), tpi(-1), ud(_ud) {}
  ~metrotrk_t(void) { term(); }
  bool init(int port);
  void term(void);

  bool ping(void);
  bool connect(void);
  bool disconnect(void);
  bool support_mask(uchar mask[32], uchar *protocol_level);
  bool cpu_type(trk_cpuinfo_t *cpuinfo);
  int open_file(const char *name, trk_open_mode_t mode);
  ssize_t write_file(int h, const void *bytes, size_t size);
  ssize_t read_file(int h, void *bytes, size_t size);
  bool seek_file(int h, uint32 off, int seek_mode); // SEEK_...
  bool close_file(int h, int timestamp);
  bool install_file(const char *fname, char drive);
  bool install_sis_file(const char *local_sis_fname, char drive);
  bool create_process(
        const char *fname,
        const char *args,
        trk_process_info_t *pi);
  int attach_process(int pid); // returns tid
  bool resume_thread(int pid, int tid);
  bool step_thread(int pid, int tid, int32 start, int32 end, bool stepinto);
  bool suspend_thread(int pid, int tid);
  int add_bpt(int pid, int tid, int32 addr, size_t len, int count, bool thumb_mode);
  bool del_bpt(int bid);
  bool change_bpt_thread(int bid, int tid);
  bool terminate_process(int pid);
  ssize_t read_memory(int pid, int tid, int32 addr, void *bytes, size_t size);
  ssize_t write_memory(int pid, int tid, int32 addr, const void *bytes, size_t size);
  bool read_regs(int pid, int tid, int regnum, int nregs, uint32 *values);
  bool write_regs(int pid, int tid, int regnum, int nregs, const uint32 *values);
  bool get_process_list(proclist_t &proclist);
  bool get_thread_list(int pid, thread_list_t *threadlist);
  bool poll_for_event(int timeout);
  int32 current_pid(void) const { return tpi.pid; }
  bool recv_packet(uchar *seq, int timeout);
  bool send_reply_ok(uchar seq);
  uchar extract_byte(int &i);
  uint16 extract_int16(int &i);
  uint32 extract_int32(int &i);
  qstring extract_pstr(int &i);
  qstring extract_asciiz(int &i);
};

extern bool debug_debugger;

#endif
