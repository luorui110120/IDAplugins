

/****************************************************************************
 *                                                                          *
 * File    : main.c                                                         *
 *                                                                          *
 * Purpose : Generic dialog based Win32 application.                        *
 *                                                                          *
 * History : Date      Reason                                               *
 *           00/00/00  Created                                              *
 *                                                                          *
 ****************************************************************************/

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <tchar.h>
#include "ApplyDlg.h"
#include "CheckedList.h"
#include "resource.h"
#pragma comment(lib, "Comctl32.lib")

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <search.hpp>
#include <kernwin.hpp>
#include <stdio.h>



#define HEIGHT(rect) (LONG)(rect.bottom - rect.top)
#define WIDTH(rect) (LONG)(rect.right - rect.left)
#define NELEMS(a)  (sizeof(a) / sizeof((a)[0]))
#define Refresh(hwnd) RedrawWindow((hwnd), NULL, NULL, \
    RDW_ERASE|RDW_INVALIDATE|RDW_UPDATENOW)

#define CHECK_BACKFILE_INDEX 0x100
/** Prototypes **************************************************************/

static LRESULT CALLBACK MainDlgProc(HWND, UINT, WPARAM, LPARAM);

/** Global variables ********************************************************/
char g_szFilterTable[][0x20] = {".got", ".plt"};
extern HWND g_hwndMain;

static HANDLE ghInstance;

void Main_Apply_OnClose(HWND hwnd)
{
	SetForegroundWindow(g_hwndMain);
	EndDialog(hwnd, TRUE);
}
int SegWriteFile(unsigned char *lpMemAddr, unsigned char *lpInBuf, int nInBufLen, int nOffset)
{
	int iRet = 0;
	int i = 0;
	for(i = 0; i < nInBufLen; i++)
	{
		lpMemAddr[i + nOffset] = lpInBuf[i]; 
	}
	return iRet;
}
BOOL IsFilterTable(char *lpName)
{
	int i = 0;
	int nCount = sizeof(g_szFilterTable) / sizeof(g_szFilterTable[0]);
	for(i = 0; i < nCount; i++)
	{
		if( 0 == strncmp(lpName, g_szFilterTable[i], sizeof(g_szFilterTable[0])) )
		{
			return TRUE;
		}
	}
	return FALSE;
}
bool segReadBuf(ea_t ea, unsigned char *lpMen, int nSize)
{
	int i = 0;
	for(i = 0; i < nSize; i++)
	{
		lpMen[i] = get_byte(ea + i);
	}
	return true;
}
void  Apply_patches(HWND hwnd)
{
	HWND hList = GetDlgItem(hwnd,IDC_LIST_SEGMEN);
	netnode n("$ Apply SegMen");
	char szFilePath[256 * 2] = {0};
	strncpy(szFilePath, database_idb, 256);
	char *lpTmpBuf = strrchr(szFilePath, '\\') + 1;
	if(lpTmpBuf == (char*)1)
	{
		return;
	}
	*lpTmpBuf = 0;
	get_root_filename(lpTmpBuf, 256);
	msg("=============================\n");
	msg("Apply Path:%s\n", szFilePath);
	if(IsDlgButtonChecked(hwnd, IDC_APPLY_CHECK_BACK))
	{
		char szBackPath[300] = {0};
		sprintf(szBackPath, "%s.back", szFilePath);
		msg("BackFile Path:%s.back\n", szFilePath);
		CopyFile(szFilePath, szBackPath, FALSE);
		n.altset(CHECK_BACKFILE_INDEX, 1);
	}
	else
	{
		n.altset(CHECK_BACKFILE_INDEX, 0);
	}
	HANDLE hFile=CreateFile(szFilePath, GENERIC_WRITE | GENERIC_READ, 0, 
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);   //获得文件句柄
	HANDLE hMapping=CreateFileMapping(hFile,NULL,PAGE_READWRITE,0,0,NULL);  //创建内存映射对象
	if(INVALID_HANDLE_VALUE == hMapping)
	{
		msg("CreateFileMapping :%08X ErrorCode:%d\n", hMapping, GetLastError());
		return ;
	}
	unsigned char* pvFile=(unsigned char*)MapViewOfFile(hMapping,FILE_MAP_ALL_ACCESS,0,0,0); //创建视图 就是映射文件到内存;

	int i;
	segment_t *curseg;
	int seg_qty = get_segm_qty();
	for(i=0 ; i < seg_qty; i++)
	{
		char segname[0x100] = {0};
		curseg = getnseg(i);
		get_true_segm_name(curseg, segname, 255);
		int offset = get_fileregion_offset(curseg->startEA);
		int nSize = curseg->endEA - curseg->startEA;
		int nSelectStat = CheckedListBox_GetCheckState(hList, i);
		n.altset(i, nSelectStat);
		if(offset > 0 && nSelectStat)
		{
			//msg("offset:%X  segname:%s EA:%08X, nSize: %X\n", offset, segname, curseg->startEA, nSize);
			unsigned char *lpMem = (unsigned char*)malloc(nSize + 1);
			memset(lpMem, 0, nSize + 1);
			//if(get_many_bytes(curseg->startEA, lpMem, nSize))
			if(segReadBuf(curseg->startEA, lpMem, nSize))
			{
				msg("Apply SegMenName: %s\n", segname);
				SegWriteFile(pvFile, lpMem, nSize, offset);
			}
			//msg("lpMem:%X\n", lpMem);
			free(lpMem);
		}

		//	msg("Name:%s, StartEA:%08X, Offset:%08X, EndEA:%08X\n", segname, curseg->startEA, offset, curseg->endEA);


	}
	CloseHandle(hMapping);
	//	msg("CloseHandle(hMapping)\n");
	if(0 == UnmapViewOfFile(pvFile) )
	{
		msg("文件同步失败! ErrorCode:%d\n", GetLastError());
	}
	else
	{
		msg("文件同步成功!\n");
		msg("=============================\n");
	}
	//	msg("UnmapViewOfFile(pvFile);\n");
	CloseHandle(hFile);
	
	return;
}
void MoveWindowCenter(HWND hWndParent, HWND hWndSub)
{
	RECT rcDlg;
	GetWindowRect(hWndSub, &rcDlg);
	RECT rcParent;
	GetClientRect(hWndParent, &rcParent);
	POINT ptParentInScreen;
	ptParentInScreen.x = rcParent.left;
	ptParentInScreen.y = rcParent.top;
	::ClientToScreen(hWndParent, (LPPOINT)&ptParentInScreen);
	SetWindowPos(hWndSub, NULL, ptParentInScreen.x + (rcParent.right - rcParent.left - (rcDlg.right - rcDlg.left)) / 2, ptParentInScreen.y + (rcParent.bottom - rcParent.top - (rcDlg.bottom - rcDlg.top)) / 2, 0, 0,  SWP_NOZORDER | SWP_NOSIZE);
}
void Main_Apply_OnCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify)
{
	switch(id)
	{
		case IDOK:
		{
		//	EndDialog(hwnd, TRUE);
			Apply_patches(hwnd);
			Main_Apply_OnClose(hwnd);
		}
			break;
		case IDC_LIST_SEGMEN:
		{
		/*	switch(codeNotify)
			{
				case LBCN_ITEMCHECK:
					Static_SetText(GetDlgItem(hwnd,IDC_LBL),_T("ItemCheck"));
					break;
				case LBN_SELCHANGE:
					Static_SetText(GetDlgItem(hwnd,IDC_LBL),_T("SelectedIndexChanged"));
					break;
			}
			*/
		}
			break;
	}
}

BOOL Main_Apply_OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam)
{
	HWND hList = GetDlgItem(hwnd,IDC_LIST_SEGMEN);

	CheckedListBox_SetFlatStyleChecks(hList, TRUE);
	
	

	char szFilePath[256 * 2] = {0};
	strncpy(szFilePath, database_idb, 256);
	char *lpTmpBuf = strrchr(szFilePath, '\\') + 1;
	if(lpTmpBuf == (char*)1)
	{
		return FALSE;
	}
	*lpTmpBuf = 0;
	get_root_filename(lpTmpBuf, 256);
	HANDLE hFile=CreateFile(szFilePath, GENERIC_WRITE | GENERIC_READ, 0, 
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);   //获得文件句柄
	if(hFile == INVALID_HANDLE_VALUE)
	{
		msg("Apply Path:%s\n", szFilePath);
		msg("失败!目标%s文件不存在 或 文件无法打开    ErrorCode:%d\n", szFilePath, GetLastError());
		MoveWindowCenter(g_hwndMain, hwnd);
		return FALSE;
	}
	CloseHandle(hFile);
	int i;
	segment_t *curseg;
	int seg_qty = get_segm_qty();
	netnode n("$ Apply SegMen");
	if(BADNODE == (nodeidx_t)n)
	{
		netnode n("$ Apply SegMen", 0, true);
		for(i=0 ; i < seg_qty; i++)
		{
			BOOL bStats = FALSE;
			char segname[0x100] = {0};
			curseg = getnseg(i);
			get_true_segm_name(curseg, segname, 255);
			ListBox_InsertString(hList, -1, segname);
			bStats = !IsFilterTable(segname);
			if(bStats)
			{
				msg("segname:%s, type:%d\n", segname, curseg->type);
				bStats = curseg->type == SEG_CODE;
			}
			if(get_fileregion_offset(curseg->startEA) > 0)
			{
				CheckedListBox_SetCheckState(hList, i, bStats);
				n.altset(i, bStats);
			}

		}
		n.altset(CHECK_BACKFILE_INDEX, 1);
		CheckDlgButton( hwnd,IDC_APPLY_CHECK_BACK,   BST_CHECKED   );
	}
	else
	{
		for(i=0 ; i < seg_qty; i++)
		{
			char segname[0x100] = {0};
			curseg = getnseg(i);
			get_true_segm_name(curseg, segname, 255);
			ListBox_InsertString(hList, -1, segname);
			if(get_fileregion_offset(curseg->startEA) > 0)
			{
				CheckedListBox_SetCheckState(hList, i, n.altval(i));
			}
		}
		if(n.altval(CHECK_BACKFILE_INDEX))
		{
			CheckDlgButton( hwnd, IDC_APPLY_CHECK_BACK,  BST_CHECKED  );
		}
	}
	
	MoveWindowCenter(g_hwndMain, hwnd);
	return FALSE;
}

void Main_Apply_OnSize(HWND hwnd, UINT state, int cx, int cy)
{
    RECT rcOk = {0};
    GetWindowRect(GetDlgItem(hwnd,IDOK),&rcOk);

    RECT rcLb = {0};
    GetWindowRect(GetDlgItem(hwnd,IDC_APPLY_CHECK_BACK),&rcLb);

    MoveWindow(GetDlgItem(hwnd,IDC_LIST_SEGMEN),0,0,
        cx, cy - (HEIGHT(rcOk) + 2),TRUE);
    MoveWindow(GetDlgItem(hwnd,IDOK), cx - WIDTH(rcOk),
        cy - HEIGHT(rcOk), WIDTH(rcOk),HEIGHT(rcOk),TRUE);

    //Refresh label
    MoveWindow(GetDlgItem(hwnd,IDC_APPLY_CHECK_BACK), 1,
        cy - HEIGHT(rcOk) + 1, cx - WIDTH(rcOk) - 4, HEIGHT(rcOk) - 2,TRUE);
    Refresh(GetDlgItem(hwnd,IDC_APPLY_CHECK_BACK)); //And label contents

}

/// @brief Set the colors used to paint controls in WM_CTLCOLORLISTBOX handler.
///
/// @param hdc Handle of a device context.
/// @param TxtColr Desired text color.
/// @param BkColr Desired back color.
///
/// @returns HBRUSH A reusable brush object.
HBRUSH SetColor(HDC hdc, COLORREF TxtColr, COLORREF BkColr)
{
    static HBRUSH ReUsableBrush;
	DeleteObject(ReUsableBrush);
    ReUsableBrush = CreateSolidBrush(BkColr);
    SetTextColor(hdc, TxtColr);
    SetBkColor(hdc, BkColr);
    return ReUsableBrush;
}

HBRUSH Main_Apply_OnCtlColorListbox(HWND hwnd, HDC hdc, HWND hwndChild, int type)
{
	return SetColor(hdc, GetSysColor(COLOR_BTNTEXT), GetSysColor(COLOR_BTNFACE));
}

BOOL CALLBACK Main_Apply_DlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch(msg)
	{
		HANDLE_MSG (hwndDlg, WM_CLOSE, Main_Apply_OnClose);
		HANDLE_MSG (hwndDlg, WM_COMMAND, Main_Apply_OnCommand);
		HANDLE_MSG (hwndDlg, WM_INITDIALOG, Main_Apply_OnInitDialog);
		HANDLE_MSG (hwndDlg, WM_SIZE, Main_Apply_OnSize);
		HANDLE_MSG (hwndDlg, WM_CTLCOLORLISTBOX, Main_Apply_OnCtlColorListbox);

		default: return FALSE;
	}
}

int PASCAL ApplyWinMain(HINSTANCE hInstance)
{
    INITCOMMONCONTROLSEX icc;
    WNDCLASSEX wcx;
	icc.dwSize = sizeof(icc);
	icc.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&icc);

	InitCheckedListBox(hInstance);
	if(0 == ghInstance)
	{
		ghInstance = hInstance;

		

		/* Get system dialog information */
		wcx.cbSize = sizeof(wcx);
		if (!GetClassInfoEx(NULL, MAKEINTRESOURCE(32770), &wcx))
			return 0;

		/* Add our own stuff */
		wcx.hInstance = hInstance;
	//	wcx.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDR_ICO_MAIN));
		wcx.lpszClassName = _T("CheckedCClass");
		if (!RegisterClassEx(&wcx))
			return 0;
	}
    /* The user interface is a modal dialog box */
    return DialogBox(hInstance, MAKEINTRESOURCE(IDD_DLGSEGMEN), NULL, (DLGPROC)Main_Apply_DlgProc);
}
