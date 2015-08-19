
#ifndef _UNICODE_H
#define _UNICODE_H
#include <stdio.h>
#include <windows.h>
extern     const unsigned short g_TableCount;
extern	 unsigned short g_TableGB2132[][2]; 
extern   unsigned short g_TableUnicode[][2];

#define UNICODESEARCH	0
#define GB2313SEARCH	1

 void GB2132ToUnicodeInit();
void MyQsort(unsigned short lppTable[][2], int nTalbeCount);

int  GB2132ToUnicode(char*gb,int len, wchar_t *unicode);
int  UnicodeToGB2132(wchar_t *unicode,int len, char*gb); 

int UnicodeToUtf8(const wchar_t *pszUnicode, const int nLen, char *pszUtf8);
int Utf8ToUnicode(const char *pszUtf8, const int nLen, wchar_t *pszUnicode);

int Utf8ToGB2312( char *pszUtf8, const int nLen, char *pszGb2312);
int GB2312ToUtf8( char *pszGb2312, const int nLen, char *pszUtf8);

#endif





