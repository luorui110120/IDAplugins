#include "java.hpp"
#include "npooluti.hpp"

// jasmin reserved word support
#include <set>
static std::set<qstring> ResW;

//-----------------------------------------------------------------------
// as procedupre for converter only
void ResW_init(void)
{
  static char const * const jasRW[] = {
#include "jas_rw.cc"
  };

  for(unsigned i = 0; i < j_lastnorm; i++) ResW.insert(Instructions[i].name);
  ResW.insert(jasRW, jasRW+qnumber(jasRW));
}

//-----------------------------------------------------------------------
// as procedure for rw-changed
void ResW_validate(uint32 *Flags, ushort *pend)
{
  register ushort *pi = tsPtr;
  register uchar *p = (uchar *)pi;
  do {
    if ( *pi >= CHP_MAX ) return;
    *p++ = (uchar)*pi++;
  }while ( pi < pend );
  *p = '\0';
  if ( ResW.find((const char *)tsPtr) != ResW.end() ) *Flags |= _OP_JSMRES_;
}

//-----------------------------------------------------------------------
// visible for converter only
uint32 upgrade_ResW(uint32 opstr)
{
  if ( !(opstr & (_OP_NOWORD << 16)) ) { // check for upg12
#ifdef __BORLANDC__
#if offsetof(_STROP_, size) || offsetof(_STROP_, flags) != 2
#error
#endif
#endif
    uint32 len = (ushort)opstr;
    uint32 flg = (opstr >> 16) & ~_OP_JSMRES_;
    ResW_validate(&flg, tsPtr + len);
    opstr = (flg << 16) | len;
  }
  return(opstr);
}

//-----------------------------------------------------------------------

//-----------------------------------------------------------------------
uchar ResW_oldbase(void)
{
  if ( ConstantNode.altval(CNA_KWRDVER) != KEYWORD_VERSION ) {
    ResW_init();  // prepare conversion
    for(int pos = 1; (ushort)pos <= curClass.maxCPindex; pos++) {
      ConstOpis co;

      if ( ConstantNode.supval(pos, &co, sizeof(co)) != sizeof(co) ) goto badbase;
      if ( co.type != CONSTANT_Utf8 || !co._Ssize ) continue;
      if ( (co._Sflags & _OP_JSMRES_) || !(co._Sflags & _OP_NOWORD) ) {
        if ( !getblob(pos << 16, tsPtr, co._Ssize) ) goto badbase;
        uint32 v = upgrade_ResW(co._Sopstr);
        if ( v == co._Sopstr ) continue;
        ConstantNode.altset(pos << 16, v);
        co._Sopstr = v;
        ConstantNode.supset(pos, &co, sizeof(co));
      }
    }
    ResW.clear();
    ConstantNode.altset(CNA_KWRDVER, KEYWORD_VERSION);
  }
  return(1);
badbase:
  return(0);
}

//-----------------------------------------------------------------------
void ResW_newbase(void)
{
  ConstantNode.altset(CNA_KWRDVER, KEYWORD_VERSION);
}

//-----------------------------------------------------------------------
void ResW_free(void)
{
  ResW.clear(); // free mem - this set not needed later
}

//-----------------------------------------------------------------------
