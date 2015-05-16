//--------------------------------------------------------------------------
static char *token2str(char *buf, size_t bufsize, GEOStoken &t)
{
  if ( t.str[0] )
    qsnprintf(buf, bufsize, "%4.4s/%u", t.str, t.num);
  else
    qstrncpy(buf, "-", bufsize);
  return buf;
}

//--------------------------------------------------------------------------
unsigned char _GeosXlate[]="€¥™š …ƒ„ †‡‚Š"
                           "ˆ‰¡Œ‹¤¢•“” £—–"
                           " ø›œùá      ’ "
                           "ìñóòæëä  ô¦§ê‘í"
                           "¨­ªûŸ÷ ®¯       "
                           "      ö˜       "
                           "                "
                           "                ",

              _GeosXlapp[]="€¥™š …ƒ„a†‡‚Š"
                           "ˆ‰¡Œ‹¤¢•“”o£—–"
                           "+ø›œùáRC~'\"Ø’0"
                           "ìñóòæëäããô¦§ê‘í"
                           "¨­ªûŸ÷®¯_ AAO™”"
                           "-Ä\"\"`'ö˜Y/è<>yY"
                           "+ú,\"pAEAEEIIIIOO"
                           " OUUU,^~-`øø,\",'";

static char *geos2ibm(char *out, char *in, size_t insize)
{
  char *saved = out;
  for ( int i=0; i < insize; i++ )
  {
    uchar c = *in++;
    if ( !c ) break;
    if ( c & 0x80 ) c = _GeosXlapp[c & 0x7F];
    *out++ = c;
  }
  *out = '\0';
  return saved;
}


