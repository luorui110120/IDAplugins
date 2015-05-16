#ifndef _OUTUTIL_HPP__
#define _OUTUTIL_HPP__

#define _CURCOL       (color_t)0
#define WARN_SYM      ('#')

#define MIN_ARG_SIZE  3
#define STR_PRESERVED 64  // overlapped (MAXSTR*2) preservation (for color)

extern size_t outcnt;
extern char   *ref_pos;
extern bool   no_prim;

int     out_commented(const char *p, color_t ntag = _CURCOL);
bool    change_line(bool main = false);
bool    checkLine(size_t size);
uchar   chkOutLine(const char *str, size_t len);
#define CHK_OUT_STR(p)  chkOutLine(p, sizeof(p)-1)
static inline void OutKeyword(const char *str, size_t len)
    { outcnt += len; out_keyword(str); }
#define OUT_KEYWORD(p)  OutKeyword(p, sizeof(p)-1)
uchar   chkOutKeyword(const char *str, unsigned len);
#define CHK_OUT_KEYWORD(p)  chkOutKeyword(p, sizeof(p)-1)
uchar   chkOutSymbol(char c);
uchar   chkOutChar(char c);
uchar   chkOutSymSpace(char c);
static inline void outLine(const char *str, unsigned len)
    { outcnt += len; OutLine(str); }
#define OUT_STR(p)  outLine(p, sizeof(p)-1)
static inline uchar chkOutDot(void)
    { return(chkOutChar('.')); }
static inline void OutSpace(void)
    { ++outcnt; OutChar(' '); }
static inline uchar chkOutSpace(void)
    { return(chkOutChar(' ')); }
uchar   putShort(ushort value, uchar wsym = WARN_SYM);
char    outName(ea_t from, int n, ea_t ea, uval_t off, uchar *rbad);
uchar   putVal(op_t &x, uchar mode, uchar warn);
uchar   OutUtf8(ushort index, fmt_t mode, color_t ntag = _CURCOL);
uchar   out_index(ushort index, fmt_t mode, color_t ntag, uchar as_index);
uchar   out_alt_ind(uint32 val);
void    out_method_label(uchar is_end);
uchar   outOffName(ushort off);
bool    block_begin(uchar off);
bool    block_end(uint32 off);
bool    block_close(uint32 off, const char *name);
bool    close_comment(void);
uchar   out_nodelist(uval_t nodeid, uchar pos, const char *pref);
void    init_prompted_output(char str[MAXSTR*2], uchar pos = 0);
uchar   OutConstant(op_t& x, uchar impdsc = 0);
void    myBorder(void);
uchar   out_problems(char str[MAXSTR], const char *prefix);
uchar   putScope(ushort scope, uint32 doff);
size_t  debLine(void);
void    instr_beg(char str[MAXSTR*2], int mode);

// in out.cpp
size_t  putDeb(uchar next);

#endif
