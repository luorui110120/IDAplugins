
// IOCTL codes for the win32 debugger

#define WIN32_IOCTL_RDMSR    0 // read model specific register
#define WIN32_IOCTL_WRMSR    1 // write model specific register
#define WIN32_IOCTL_STARTPDB 2 // client->server: start getting symbols for a file
                               // compiler_info_t cc;
                               // ea64 base_ea;
                               // char *pdbfile; // path to input file or PDB
                               // char *dpath;   // PDB cache path
                               // char *spath;   // full sympath
                               // returns: 0 - not supported
                               //         -2 - error (text in output buffer)
                               //         >0 - conversion id
#define WIN32_IOCTL_DONEPDB  3 // client->server: check if PDB conversion is finished
                               // uint32 id; // conversion id
                               // returns: 0 - not supported
                               //         -2 - error (text in output buffer)
                               //          1 - in progress
                               //          2 - done, til filename in output buffer
#define WIN32_IOCTL_RMFILE   4 // client->server: remove a remote file
                               // const char *filename;
                               // returns: 1 - ok
                               //         -2 - error (text in output buffer)
#define WIN32_IOCTL_READFILE 5 // server->client: read bytes from the input file
                               //  uint64 offset;
                               //  uint32 length;
                               // returns: 1 - ok
                               //         -2 - error (text in output buffer)

// WIN32_IOCTL_WRMSR uses this structure:
struct win32_wrmsr_t
{
  uint32 reg;
  uint64 value;
};

