#if defined(__LINUX__) && defined(LIBWRAP)
#include <stdlib.h>
#include <syslog.h>
#include <tcpd.h>
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;
const char *check_connection(int rpc_socket)
{
    struct request_info req;

    /* fill req struct with port name and fd number */
    resident = 1;
    request_init(&req, RQ_DAEMON, "idal", RQ_FILE, rpc_socket, NULL);
    fromhost(&req);
    if(!hosts_access(&req)) return(eval_client(&req));
    return(NULL);
}
    
#endif
