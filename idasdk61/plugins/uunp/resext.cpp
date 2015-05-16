
// Written by Yury Haron yjh@styx.cabel.net

#include <windows.h>

#include <ida.hpp>
#include <prodir.h>
#include <idp.hpp>
#include <bytes.hpp>
#include "uunp.hpp"

static FILE    *fr;
static ea_t     ResBase;
static uint32   ResTop;
static asize_t  ImgSize;
static struct
{
  union
  {
    wchar_t *name;
    uint16  Id;
  };
  uint32    len;
} Names[3];

//--------------------------------------------------------------------------
#pragma pack(push, 1)
struct rhdr_beg_t
{
  uint32 DataSize;
  uint32 HeaderSize;
};

struct rhdr_end_t
{
  uint32 DataVersion;
  uint16 MemoryFlags;
  uint16 LanguageId;
  uint32 Version;
  uint32 Characteristrics;
};

union rhdr_name_t
{
  struct
  {
    uint16 prefix;  // = 0xFFFF if number entry
    uint16 Id;      // for number entry
  };
  wchar_t Name[1];  // zero terminated
};

struct reshdr_t
{
  rhdr_beg_t  rb;
  rhdr_name_t Type;
  rhdr_name_t Name;
  rhdr_end_t  re;
};
#pragma pack()

// resources are always aligned to sizeof(uint32)

//---------------------------------------------------------------------------
static void store(const void *Data, uint32 size)
{
  static rhdr_end_t   re;
  static rhdr_name_t  zname = { { 0xFFFF } };
  static const uint32 zero4 = 0;

  rhdr_beg_t rh;
  size_t len = sizeof(rh) + sizeof(re);

  if ( Names[0].len != 0 )
    len += Names[0].len;
  else
    len += sizeof(zname);

  if ( Names[1].len != 0 )
    len += Names[1].len;
  else
    len += sizeof(zname);

  rh.HeaderSize = (uint32)len;
  rh.DataSize   = size;
  re.LanguageId = Names[2].Id;
  qfwrite(fr, &rh, sizeof(rh));

  if ( Names[0].len != 0 )
  {
    qfwrite(fr, Names[0].name, Names[0].len);
  }
  else
  {
    zname.Id = Names[0].Id;
    qfwrite(fr, &zname, sizeof(zname));
  }

  if ( Names[1].len != 0 )
  {
    qfwrite(fr, Names[1].name, Names[1].len);
  }
  else
  {
    zname.Id = Names[1].Id;
    qfwrite(fr, &zname, sizeof(zname));
  }

  qfwrite(fr, &re, sizeof(re));
  if ( Data )  // for 'primary' header
  {
    qfwrite(fr, Data, size);
    len += size;
  }
  if ( len & 3 )
    qfwrite(fr, &zero4, 4 - (len & 3));
}

//---------------------------------------------------------------------------
static bool initPtrs(const char *fname)
{
  IMAGE_DATA_DIRECTORY  res;
  ea_t nth;

  nth = get_long(curmod.startEA + 0x3C) + curmod.startEA;

  size_t off = offsetof(IMAGE_NT_HEADERS,
                OptionalHeader.DataDirectory
                  [IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);

  if ( !get_many_bytes(nth + off, &res, sizeof(res))
    || !res.VirtualAddress
    || !res.Size )
  {
    msg("There are no resources in the module\n");
    return false;
  }

  ResBase = curmod.startEA + res.VirtualAddress;
  ResTop  = res.Size;
  ImgSize = curmod.endEA - curmod.startEA;

  int minres = 2*sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)+3*sizeof(IMAGE_RESOURCE_DIRECTORY);
  if ( (res.Size & 3) != 0
    || res.Size <= minres
    || res.VirtualAddress >= ImgSize
    || res.Size >= ImgSize
    || res.Size + res.VirtualAddress > ImgSize )
  {
    msg("Invalid resource descriptor\n");
    return false;
  }

  fr = qfopen(fname, "wb");
  if ( fr == NULL )
  {
    msg("Can not create the output file '%s' for the resources\n", fname);
    return false;
  }

  return true;
}

//---------------------------------------------------------------------------
static bool extractData(uint32 off)
{
  IMAGE_RESOURCE_DATA_ENTRY rd;

  if ( off + sizeof(rd) > ResTop ) return false;
  if ( !get_many_bytes(ResBase + off, &rd, sizeof(rd)) ) return false;

  if ( rd.OffsetToData >= ImgSize
    || rd.Size > ImgSize
    || rd.OffsetToData + rd.Size > ImgSize ) return false;

  void *data = qalloc(rd.Size);
  if ( data == NULL )
  {
    msg("Not enough memory for resources\n");
    return false;
  }
  bool res = false;
  if ( get_many_bytes(curmod.startEA + rd.OffsetToData, data, rd.Size) )
  {
    store(data, rd.Size);
    res = true;
  }
  qfree(data);
  return res;
}

//---------------------------------------------------------------------------
static bool extractDirectory(uint32 off, int level);

static bool extractEntry(uint32 off, int level, bool named)
{
  IMAGE_RESOURCE_DIRECTORY_ENTRY  rde;

  if ( off + sizeof(rde) >= ResTop )
    return false;
  if ( !get_many_bytes(ResBase + off, &rde, sizeof(rde)) )
    return false;

  if ( (bool)rde.NameIsString != named )
    return false;

  if ( (bool)rde.DataIsDirectory != (level != 2) )
    return false;

  off += sizeof(rde);

  if ( !named )
  {
    Names[level].Id = rde.Id;
  }
  else
  {
    ea_t npos = rde.NameOffset;
    if( npos < off || npos + 2 >= ResTop )
      return false;
    uint32 nlen = get_word(npos + ResBase)*sizeof(wchar_t);
    if ( !nlen || npos + nlen > ResTop )
      return false;
    wchar_t *p = (wchar_t *)qalloc(nlen + sizeof(wchar_t));
    if ( p == NULL )
    {
      msg("Not enough memory for resource names\n");
      return false;
    }
    if ( !get_many_bytes(npos + sizeof(uint16) + ResBase, p, nlen) )
    {
bad_name:
      qfree(p);
      return false;
    }
    p[nlen/sizeof(wchar_t)] = 0;
    size_t wlen = wcslen(p);
    if ( !wlen || wlen < nlen/2-1 ) goto bad_name;
    Names[level].name = p;
    Names[level].len = uint32((wlen+1)*sizeof(wchar_t));
  }

  if ( level != 2 )
  {
    bool res = false;
    if ( rde.OffsetToDirectory >= off )
      res = extractDirectory(rde.OffsetToDirectory, level+1);

    if ( Names[level].len ) qfree(Names[level].name);
    Names[level].name = NULL;
    Names[level].len  = 0;
    return res;
  }

  if ( rde.OffsetToData < off )
    return false;

  return extractData(rde.OffsetToData);
}

//---------------------------------------------------------------------------
static bool extractDirectory(uint32 off, int level)
{
  IMAGE_RESOURCE_DIRECTORY  rd;

  if ( off + sizeof(rd) >= ResTop )
    return false;
  if ( !get_many_bytes(ResBase + off, &rd, sizeof(rd)) )
    return false;

  off += sizeof(rd);
  if ( rd.NumberOfNamedEntries != 0 )
  {
    if ( level == 2 )           // language must be ONLY numbered
      return false;
    do
    {
      if ( !extractEntry(off, level, true) )
        return false;
      off += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
    } while ( --rd.NumberOfNamedEntries );
  }
  if ( rd.NumberOfIdEntries != 0 )
  {
    do
    {
      if ( !extractEntry(off, level, false) )
        return false;
      off += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
    } while ( --rd.NumberOfIdEntries );
  }
  return true;
}

//---------------------------------------------------------------------------
void extract_resource(const char *fname)
{
  if ( !initPtrs(fname) )
    return;

  store(NULL, 0); // zero-resource header

  bool wrerr = false;
  bool res = extractDirectory(0, 0);
  if ( !res )
  {
    msg("Can't extract resource (possible it is invalid)\n");
  }
  else
  {
    qflush(fr);
    if ( ferror(fr) || feof(fr) )
      wrerr = true;
  }
  if ( qfclose(fr) )
    wrerr = true;
  if ( res && wrerr )
    msg("Error writing resource file\n");

  if ( !res || wrerr )
    unlink(fname);
  else
    msg("Resources have been extracted and stored in '%s'\n", fname);
}

