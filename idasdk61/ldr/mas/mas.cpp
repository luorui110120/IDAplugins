
// Loader for the Macro-assembler-related binary format

#include "../idaldr.h"
#include <exehdr.h>
#include <queue.hpp>
#include <stddef.h>
#include "mas.hpp"

// undefine this to print some debugging information
// in the IDA console.
//#define DEBUG

//-----------------------------------------------------------------------------
struct gas_family {
    uchar code;
    const char *processor;
};

static const struct gas_family families [] = {
    { 0x01,     "68k"       },
    // 0x03 : M*Core
    { 0x05,     "ppc"       },
    { 0x09,     "dsp56k"    },
    { 0x11,     "m740"      },
    // 0x12 : MELPS-4500
    // 0x13 : M16
    // 0x14 : M16C
    // 0x15 : F2MC8L
    { 0x16,     "f2mc16l"   },
    { 0x19,     "m7700"     },
    // 0x21 : MCS-48
    // 0x25 : SYM53C8xx
    // 0x29 : 29xxx
    { 0x2A,     "i960b"     },  // little or big endian ????
    // 0x31 : MCS-51
    { 0x32,     "st9"       },
    { 0x33,     "st7"       },
    // 0x38 : 1802/1805
    // 0x39 : MCS-96/196/296
    // 0x3A : 8X30x
    { 0x3B,     "avr"       },
    // 0x3C : XA
    // 0x3F : 4004/4040
    { 0x41,     "8085"      },
    { 0x42,     "8086"      },
    { 0x47,     "tms320c6"  },
    // 0x48 : TMS9900
    // 0x49 : TMS370xxx
    // 0x4A : MSP430
    { 0x4B,     "tsm32054"  },
    { 0x4C,     "c166"      },
    { 0x51,     "z80"       },
    // 0x52 : TLCS-900
    // 0x53 : TLCS-90
    // 0x54 : TLCS-870
    // 0x55 : TLCS-47
    // 0x56 : TLCS-9000
    { 0x61,     "6800"      },
    { 0x62,     "6805"      },
    { 0x63,     "6809"      },
    // 0x64 : 6804
    // 0x65 : 68HC16
    // 0x66 : 68HC12
    // 0x67 : ACE
    { 0x68,     "h8300"     },
    { 0x69,     "h8500"     },
    // 0x6C : SH7000
    // 0x6C : SC14xxx
    // 0x6C : SC/MP
    // 0x6C : COP8
    { 0x70,     "pic16cxx"  },
    { 0x71,     "pic16cxx"  },
    // 0x72 : PIC17C4x
    // 0x73 : TMS-7000
    // 0x74 : TSM3201x
    // 0x75 : TSM320C2x
    // 0x76 : TSM320C3x
    { 0x77,     "tms320c2"  },
    // 0x78 : ST6µPD772
    { 0x79,     "z8"        }
    // 0x7A : µPD78(C)10
    // 0x7B : 75K0
    // 0x7C : 78K0
    // 0x7D : µPD7720
    // 0x7E : µPD7725
    // 0x7F : µPD77230
};

static char creator[MAXSTR];   // program name which created the binary
static int entry_point;        // address of the entry point

//-----------------------------------------------------------------------------
// output an error and exit loader.
static void mas_error(const char *format, ...) {
    char b[MAXSTR];
    va_list va;

    va_start(va, format);
    qvsnprintf(b, sizeof b, format, va);
    va_end(va);
    loader_failure("mas loader critical error : %s", b);
}

//-----------------------------------------------------------------------------
// set the current processor type according to "cpu_type".
static bool mas_set_cpu(uchar cpu_type) {
    for (int i = 0; i < qnumber(families); i++) {
        if ( families[i].code != cpu_type )
            continue;

        set_processor_type(families[i].processor, SETPROC_ALL|SETPROC_FATAL);
#if defined(DEBUG)
        msg("MAS: detected processor %s\n", families[i].processor);
#endif
        return true;
    }
    return false;
}

//-----------------------------------------------------------------------------
// return a segment name according to its "segment_type".
static const char * mas_get_segname(uchar segment_type) {
    switch ( segment_type ) {
        case 0x00:  return "UNDEFINED";
        case 0x01:  return "CODE";
        case 0x02:  return "DATA";
        case 0x03:  return "IDATA";
        case 0x04:  return "XDATA";
        case 0x05:  return "YDATA";
        case 0x06:  return "BDATA";
        case 0x07:  return "IO";
        case 0x08:  return "REG";
        case 0x09:  return "ROMDATA";
    }
    return NULL;
}

//-----------------------------------------------------------------------------
// write comments.
static void mas_write_comments(void) {
    create_filename_cmt();

    char entry_point_str[20];
    if ( entry_point == -1 )
        qstrncpy(entry_point_str, "NOT DETECTED", sizeof(entry_point_str));
    else
        qsnprintf(entry_point_str, sizeof entry_point_str, "0x%X", entry_point);

    // write name of the creator program
    add_pgm_cmt("Creator program   : %s", creator);
    // write address of the entry point
    add_pgm_cmt("Entry point       : %s", entry_point_str);
}

//-----------------------------------------------------------------------------
// detect macro assembler files using the start sequence.
int idaapi accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n) {
    short word = 0;

    if ( n )
        return 0;

    // read the first word
    if ( qlread(li, &word, 2) != 2 )
        return 0;

#if defined(DEBUG)
    msg("MAS: 2 first bytes : 0x%X\n", word);
#endif

    // first word must match the start_sequence
    if ( word != START_SEQUENCE )
        return 0;

    qstrncpy(fileformatname, "Macro Assembler by Alfred Arnold", MAX_FILE_FORMAT_NAME);
#if defined(DEBUG)
    msg("MAS: detected mas binary file !\n");
#endif
    return 1;
}

//-----------------------------------------------------------------------------
// process a file record according to its "record_type".
// return true if there is no more records to process.
static bool process_record(linput_t *li, const uchar record_type, bool load) {
    bool finished = false;

    switch ( record_type ) {

        // A record with a header byte of $81 is a record that may contain code or
        // data from arbitrary segments.
        //
        // header      : 1 byte
        // segment     : 1 byte
        // gran        : 1 byte
        // start_addr  : 4 bytes (entry point)
        // length      : 2 bytes
        // data        : length bytes
        case 0x81:
            {
                mas_header_t header;
                memset(&header, 0, sizeof header);

                // read the header
                if ( qlread(li, &header, sizeof header) != sizeof header )
                    mas_error("unable to read header (%d bytes)", sizeof header);

                // granularities that differ from 1 are rare and mostly appear
                // in DSP CPU's that are not designed for byte processing.
                if ( header.gran != 1 )
                    mas_error("unsupported granularity (%d)", header.gran);

                // set processor
                if ( !mas_set_cpu(header.header) )
                    mas_error("processor type '0x%X' is currently unsupported",
                        header.header);
                if ( !load ) // we have the processor, nothing else to do
                {
                  finished = true;
                  break;
                }

                // get segment name
                const char *segname = mas_get_segname(header.segment);
                if ( segname == NULL )
                    mas_error("invalid segment '0x%X'", header.segment);

#if defined(DEBUG)
                msg("MAS: ready to read %d bytes (0x%X -> 0x%X)\n",
                    header.length, header.start_addr, header.start_addr + header.length);
#endif

                // send code in the database
                file2base(li, qltell(li), header.start_addr,
                    header.start_addr + header.length,
                    FILEREG_PATCHABLE);

                // set selector
                sel_t selector = allocate_selector(0);

                // create segment
                add_segm(selector, header.start_addr, header.start_addr + header.length,
                           segname, segname);
            }
            break;

        // The last record in a file bears the Header $00 and has only a string as
        // data field. This string does not have an explicit length specification;
        // its end is equal to the file's end.
        //
        // The string contains only the name of the program that created the file
        // and has no further meaning.
        //
        // creator     : x bytes
        case 0x00:
            {
                uint32 length = qlsize(li) - qltell(li);
#if defined(DEBUG)
                msg("MAS: creator length : %ld bytes\n", length);
#endif
                if ( length >= sizeof creator )
                    mas_error("creator length is too large (%ld >= %ld",
                        length, sizeof creator);
                ssize_t tmp;
                if ( (tmp = qlread(li, creator, length)) != length )
                    mas_error("unable to read creator string (i read %ld)", tmp);
                creator[tmp] = '\0';
            }
            finished = true;
            break;

        // entry_point : 4 bytes
        case 0x80:
            {
                if ( qlread(li, &entry_point, 4) != 4 )
                    mas_error("unable to read entry_point");
                if ( load )
                {
#if defined(DEBUG)
                  msg("MAS: detected entry point : 0x%X\n", entry_point);
#endif
                  inf.startIP = entry_point;      // entry point
                  segment_t *s = getseg(entry_point);
                  inf.start_cs = s ? s->sel : 0;  // selector of code
                }
            }
            break;

        default:
            // start_addr  : 4 bytes
            // length      : 2 bytes
            // data        : length bytes
            if ( record_type >= 0x01 && record_type <= 0x7F ) {
                struct header {
                    int start_addr;
                    short length;
                } header;

                memset(&header, 0, sizeof header);

                // read the header
                if ( qlread(li, &header, sizeof header) != sizeof header )
                    mas_error("unable to read header (%d bytes)", sizeof header);

                if ( load )
                {
                  // send code in the database
                  file2base(li, qltell(li), header.start_addr,
                      header.start_addr + header.length,
                      FILEREG_PATCHABLE);

#if defined(DEBUG)
                  msg("MAS: i've read %d DATA bytes (0x%X -> 0x%X)\n",
                      header.length, header.start_addr, header.start_addr + header.length);
#endif

                  // set selector
                  sel_t selector = allocate_selector(0);

                  // create data segment
                  add_segm(selector, header.start_addr, header.start_addr + header.length,
                           "DATA", "DATA");
                }
                else
                  qlseek(li, qltell(li)+header.length);
            }
            else
                mas_error("invalid record type '0x%X'\n", record_type);
    }

    return finished;
}

//-----------------------------------------------------------------------------
// load a macro assembler file in IDA.
void idaapi load_file(linput_t *li, ushort /*neflag*/, const char * /*fileformatname*/) {
    // already read the 2 first bytes
    qlseek(li, 2);

    // initialize static variables
    qstrncpy(creator, "UNKNOWN", sizeof(creator));
    entry_point = -1;

    bool finished = false;

    while ( !finished ) {
        uchar record_type = 0;

        // read the record type
        if ( qlread(li, &record_type, 1) != 1 )
            mas_error("unable to read the record type");

        finished = process_record(li, record_type, true);
    }

#if defined(DEBUG)
    msg("MAS: reading complete\n");
#endif

    mas_write_comments();
}

//----------------------------------------------------------------------
bool idaapi init_loader_options(linput_t *li)
{
  // already read the 2 first bytes
  qlseek(li, 2);

  bool finished = false;
  while ( !finished ) {
    uchar record_type = 0;
    // read the record type
    if ( qlread(li, &record_type, 1) != 1 )
      return false;
    finished = process_record(li, record_type, false);
  }
  return true;
}

//-----------------------------------------------------------------------------
// Loader description block
loader_t LDSC =
{
    IDP_INTERFACE_VERSION,
    0,                            // loader flags
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
    accept_file,
//
//      load file into the database.
//
    load_file,
//
//      create output file from the database.
//      this function may be absent.
//
  NULL,
//      take care of a moved segment (fix up relocations, for example)
  NULL,
//      initialize user configurable options based on the input file.
  init_loader_options,
};
