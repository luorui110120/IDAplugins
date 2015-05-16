/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *
 *      Java Virtual Machine pseudo-loader.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

/*
        L O A D E R  for Java-classFile
*/

#include "../idaldr.h"
#include "../../module/java/classfil.hpp"

//--------------------------------------------------------------------------
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
static int idaapi accept_file(linput_t *li,
                       char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
  uint32  magic;
  uint16  min_ver, maj_ver;
  uchar   jdk;

  if(   n
     || lread4bytes(li, &magic, 1)
     || magic != MAGICNUMBER
     || lread2bytes(li, &min_ver, 1)
     || lread2bytes(li, &maj_ver, 1))
  {
    goto badfmt;
  }

  if ( maj_ver <= JDK_MIN_MAJOR ) 
  {
    if ( maj_ver < JDK_MIN_MAJOR ) 
      goto badfmt;
    jdk = (uchar)(maj_ver >= JDK_1_1_MINOR);
  } 
  else if ( maj_ver > JDK_MAX_MAJOR ) 
  {
badfmt:
    return 0;
  } 
  else 
    jdk = (uchar)(maj_ver - (JDK_MIN_MAJOR-1));

  qsnprintf(fileformatname, MAX_FILE_FORMAT_NAME,
            "JavaVM Class File (JDK 1.%u%s)", jdk,
            jdk == 3 ? "/CLDC" : "");
  return(f_LOADER);
}

//----------------------------------------------------------------------
//      initialize user configurable options based on the input file.
static bool idaapi init_loader_options(linput_t*)
{
  set_processor_type("java", SETPROC_ALL|SETPROC_FATAL);
  return(true);
}

//--------------------------------------------------------------------------
//
//      load file into the database.
//
static void idaapi load_file(linput_t *li, ushort neflag, const char * /*fileformatname*/)
{
  if ( ph.id != PLFM_JAVA ) 
    init_loader_options(li);

  if ( ph.notify(ph.loader, li, (bool)(neflag & NEF_LOPT)) )
    error("Internal error in loader<->module link");
}

//----------------------------------------------------------------------
//
//      LOADER DESCRIPTION BLOCK
//
//----------------------------------------------------------------------
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

//----------------------------------------------------------------------
