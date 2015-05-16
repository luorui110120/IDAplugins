/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _HELP_H
#define _HELP_H
#pragma pack(push, 1)

#define HELPDYN_SET     0x7000  /* Paragraph for dynamic messages     */

typedef int help_t;     /* Help messages are referred by ints         */

enum                    /* These error codes don't use help subsystem */
{
  ErOk = 0,
  ErNoFile = -1,        /* because help subsystem is not initialized  */
  ErBadHelp = -2,       /* yet when they occur                        */
  ErBadVers = -3,
  ErIO = -4,
  ErNoMem = -5,
  ErBadOS = -6
};

/*------------------------------------------------------------------------*/
/* Function:    Initialize help subsystem.
   Input:       defaultpath - where to look for help file if other
                              methods fail.
                helpfile    - help file name
                argc,argv   - from main()
                sw          - language switcher char (for LANG variable).
                              The user can use -<sw>xx switch in the
                              command line to specify the language.
                              This switch will be deleted from argv if it exists.
   Description: Look for the help file in the following directories:
                        $(NLSPATH) - list of directories separated by
                                        : - unix
                                        ; - MS DOS
                                     This list can contain special symbols
                                       %N - help file name
                                       %L - current $LANG variable
                                            (if LANG doesn't exist, "En_US"
                                             is assumed)
                                            -<sw>xx overrides LANG variable.
                        defaultpath - the same format as NLSPATH

   Returns:     error code. Even if this function returns an error, you can
                call it again (with other parameters, of course :-)
   Example:

        code = HelpInit(getenv("FSDIR"),"fs.hlp",&argc,argv,'L');
                -- Find fs.hlp file in the directories denoted by NLSPATH
                   and FSDIR variables, if the command line contains -L##
                   switch, use '##' for the language name. E.g., if the user
                   starts this program using command line:
                        startprg -LRussian
                   the language name will be 'Russian' and the %L sequence in
                   the NLSPATH and FSDIR will be substituted by 'Russian'
*/

int HelpInit(const char *defaultpath, const char *helpfile, int *argc, char *argv[], char sw);

idaman THREAD_SAFE char *ida_export ivalue(help_t mes, char *buf, size_t bufsize);
idaman THREAD_SAFE char *ida_export qivalue(help_t mes); // Return answer in dynamic memory

#ifdef __cplusplus

/*      This class is used for temporary message:               */
/*              the message is kept until it goes out of scope. */
/*      simply use: itext(n)                                    */

class itext
{
  char *ptr;
public:
  itext(help_t mes) { ptr = qivalue(mes); }
  ~itext(void)      { qfree(ptr); }
  operator char*()  { return ptr; }
};

#ifdef __KERNWIN_HPP
NORETURN inline void Err(help_t format, ...)
{
  va_list va;
  va_start(va, format);
  verror(itext(format), va);
  // NOTREACHED
}

inline void Warn(help_t format, ...)
{
  va_list va;
  va_start(va, format);
  vwarning(itext(format), va);
  va_end(va);
}


inline void Info(help_t format, ...)
{
  va_list va;
  va_start(va, format);
  vinfo(itext(format), va);
  va_end(va);
}


inline int Message(help_t format,...)
{
  va_list va;
  va_start(va, format);
  int nbytes = vmsg(itext(format), va);
  va_end(va);
  return nbytes;
}

inline int askyn_v(int deflt, help_t format, va_list va)
{
  return askyn_cv(deflt, itext(format), va);
}

inline int askyn(int deflt, help_t format, ...)
{
  va_list va;
  va_start(va, format);
  int code = askyn_cv(deflt, itext(format), va);
  va_end(va);
  return code;
}
#endif

#endif /* __cplusplus */

#pragma pack(pop)
#endif /* _HELP_H */
