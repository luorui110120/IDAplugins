#ifndef _RESWORD_HPP__
#define _RESWORD_HPP__

void  ResW_init(void);
void  ResW_validate(uint32 *Flags, ushort *pend);
uchar ResW_oldbase(void);
void  ResW_newbase(void);
void  ResW_free();

#endif
