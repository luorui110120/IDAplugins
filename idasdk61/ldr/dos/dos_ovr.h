/*
 *      Interactive disassembler (IDA).
 *      Version 3.00
 *      Copyright (c) 1990-94 by Ilfak Guilfanov. (2:5020/209@fidonet)
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _DOS_OVR_H_
#define _DOS_OVR_H_

int  pos_read(linput_t *fp, uint32 pos, void *buf, size_t size);
int  CheckCtrlBrk(void);
void add_segm_by_selector(sel_t base, const char *sclass);
extern const char e_exe[];
//
enum o_type { ovr_noexe, ovr_pascal, ovr_cpp, ovr_ms };

o_type PrepareOverlayType(linput_t *fp, exehdr *E);
linput_t *CheckExternOverlays(void);
sel_t  LoadCppOverlays(linput_t *fp);
sel_t  LoadMsOverlays(linput_t *fp, bool PossibleDynamic);
void   LoadPascalOverlays(linput_t *fp);

NORETURN void errstruct(void);

#endif
