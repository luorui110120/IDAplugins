
#ifndef COMPRESS_HPP
#define COMPRESS_HPP

#include <diskio.hpp>

#pragma pack(push, 1)

// compress data.
// This function depends on the value of legacy_idb, so it is not completely
// thread safe. However, legacy_idb does not change its value.
idaman THREAD_SAFE int ida_export zip_deflate(
        void *ud,
        ssize_t (idaapi *file_reader)(void *ud, void *buf, size_t size),
        ssize_t (idaapi *file_writer)(void *ud, const void *buf, size_t size));

// uncompress data
// This function depends on the value of legacy_idb, so it is not completely
// thread safe. However, legacy_idb does not change its value.
idaman THREAD_SAFE int ida_export zip_inflate(
        void *ud,
        ssize_t (idaapi *file_reader)(void *ud, void *buf, size_t size),
        ssize_t (idaapi *file_writer)(void *ud, const void *buf, size_t size));

// Process zip file and enumerate all files stored in it
/* returns PK-type error code */
idaman THREAD_SAFE int ida_export process_zipfile(
        const char *zipfile,                        // name of zip file
        int (idaapi *_callback)(                    // callback for each file
                         void *ud,                  // user data
                         int32 offset,              // offset in the zip file
                         int method,                // compression method
                         uint32 csize,              // compressed size
                         uint32 ucsize,             // uncompressed size
                         uint32 attributes,
                         const char *filename),
        void *ud);                                  // user data

// error codes
#define PKZ_OK            0
#define PKZ_ERRNO         1
#define PKZ_STREAM_ERROR  2
#define PKZ_DATA_ERROR    3
#define PKZ_MEM_ERROR     4
#define PKZ_BUF_ERROR     5
#define PKZ_VERSION_ERROR 6
#define PKZ_RERR          777   // read error
#define PKZ_WERR          778   // write error

#define STORED            0    /* compression methods */
#define SHRUNK            1
#define REDUCED1          2
#define REDUCED2          3
#define REDUCED3          4
#define REDUCED4          5
#define IMPLODED          6
#define TOKENIZED         7
#define DEFLATED          8
#define NUM_METHODS       9    /* index of last method + 1 */

extern bool legacy_idb;         // for old idb files

enum linput_close_code_t        // upon closing outer linput, perform the
{                               // following action:
  LOC_CLOSE,    // close the inner linput
  LOC_UNMAKE,   // unmake the inner linput
  LOC_KEEP,     // do nothing
};

// Create a linput to read a compressed input stream
//      in - linput with compressed data, seeked to the stream beginning
//      insize - size of compressed data. -1 - unknown
//      loc - what to do upon closing the resulting linput
// Returns: linput that can be used to read uncompressed data
//          NULL if any error (no more linput descriptors)

idaman THREAD_SAFE linput_t *ida_export create_zip_linput(
        linput_t *in,
        ssize_t insize=-1,
        linput_close_code_t loc=LOC_CLOSE);

#pragma pack(pop)
#endif
