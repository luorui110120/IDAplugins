#ifndef __CALCPAGEDLG1_HEADER_
#define __CALCPAGEDLG1_HEADER_
#include <Windows.h>
#include "resource.h"
//#include "Header.h"
#define ASCIINUM	128
#define SHOWCOLUMN	5
typedef struct
{
	UINT   ID_ASC;
	UINT   ID_DEC;
	UINT   ID_HEX;
} DataDir_ASCID;
typedef struct
{
	UINT   ID_ASC;
	UINT   ID_DEC;
	UINT   ID_HEX;
	UINT   ID_CHAR;
} TitleDir_ID;

void InitDlg(HWND hwnd);
void HexCharUpperASC(char *s);
LRESULT ChangColor(HWND hwnd,HWND subHwnd,WPARAM wParam);
void InitDlgTitle(HWND hwnd);
INT_PTR CALLBACK AsciiDlgProc(HWND hwndDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);  
#endif