#ifndef __RPC_SERVER__
#define __RPC_SERVER__

#define VERBOSE_ENABLED
#include "rpc_engine.h"

class rpc_server_t: public rpc_engine_t
{
private:
  debug_event_t ev;
  debug_event_t pending_event;
  debmod_t *dbg_mod;
  FILE *channels[16];
protected:
  void close_all_channels();
  void clear_channels();
  int find_free_channel();
public:
  void set_debugger_instance(debmod_t *instance);
  debmod_t *get_debugger_instance();
  bool rpc_sync_stub(const char *server_stub_name, const char *ida_stub_name);
  int send_debug_names_to_ida(ea_t *ea, const char *const *names, int qty);
  int send_debug_event_to_ida(const debug_event_t *ev, int rqflags);
  virtual bytevec_t perform_request(const rpc_packet_t *rp);
  virtual int poll_events(int timeout_ms);
  virtual ~rpc_server_t();
  rpc_server_t(SOCKET rpc_socket);
};

// defined only in the single threaded version of the server:
extern rpc_server_t *g_global_server;

#endif
