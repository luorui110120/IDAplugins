/*

        Convert .DLL file to an .W32 file
                by writing the processor description string into it

        Command line:
                mkidp dll-file "description"

        The processor description string consists of short processor type
        names separated by colons. For example:

                arm:armb:arml

*/

// The processor description string should be at the offset 0x80 of the IDP file

#define IDP_DESC_START   0x80
#define IDP_DESC_END    0x200

#include <string.h>
#include <stdio.h>

//------------------------------------------------------------------------
int main(int argc,char *argv[])
{
  if ( argc < 3 ) {
    fprintf(stderr,"usage: mkidp dll-file \"description\"\n");
    return 1;
  }

  FILE *fp = fopen(argv[1],"rb+");
  if ( fp == NULL )
  {
    fprintf(stderr,"mkidp: can't open file '%s'\n",argv[1]);
    return 1;
  }

  fseek(fp, 0x3C ,SEEK_SET);
  int peoff;
  if ( fread(&peoff, 1, sizeof(int), fp) != sizeof(int) )
  {
    fprintf(stderr,"%s: read error\n",argv[1]);
    return 1;
  }

  int total = peoff - IDP_DESC_START;
  int len   = strlen(argv[2]) + 1;
  int zeroes= total - len;
  if ( zeroes < 16+4 )
  {
    fprintf(stderr,"mkidp: too long processor description\n");
    return 1;
  }

  fseek(fp, IDP_DESC_START ,SEEK_SET);
  if ( fwrite(argv[2], len, 1, fp) != 1 )
  {
    fprintf(stderr,"%s: write description error\n",argv[1]);
    return 1;
  }
  char zero = 0;
  for ( int i=0; i < zeroes; i++ )
  {
    if ( fwrite(&zero, 1, 1, fp) != 1 )
    {
      fprintf(stderr,"%s: write zeroes error\n",argv[1]);
      return 1;
    }
  }
  fclose(fp);
  return 0;
}
