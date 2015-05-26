#include "Apply.h"
#include <Shlwapi.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <search.hpp>
#include <kernwin.hpp>
#include <stdio.h>
#include <vector>
#include <string>
#include <CommCtrl.h>
#include "resource.h"


#include <commctrl.h>
#include <tchar.h>
#include <windowsx.h>


#include "CheckedList.h"




#define HEIGHT(rect) (LONG)(rect.bottom - rect.top)
#define WIDTH(rect) (LONG)(rect.right - rect.left)
#define NELEMS(a)  (sizeof(a) / sizeof((a)[0]))
#define Refresh(hwnd) RedrawWindow((hwnd), NULL, NULL, \
	RDW_ERASE|RDW_INVALIDATE|RDW_UPDATENOW)

extern HINSTANCE g_hinstPlugin;

char g_szFilterTable[][0x20] = {".got"};
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
void  Apply_patches()
{
	char szFilePath[256 * 2] = {0};
	strncpy(szFilePath, database_idb, 256);
	char *lpTmpBuf = strrchr(szFilePath, '\\') + 1;
	if(lpTmpBuf == (char*)1)
	{
		return;
	}
	*lpTmpBuf = 0;
	get_root_filename(lpTmpBuf, 256);
	msg("Apply Path:%s\n", szFilePath);
	HANDLE hFile=CreateFile(szFilePath, GENERIC_WRITE | GENERIC_READ, 0, 
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);   //获得文件句柄
	if(hFile == INVALID_HANDLE_VALUE)
	{
		msg("失败!目标%s文件不存在 或 文件无法打开    ErrorCode:%d\n", szFilePath, GetLastError());
		return;
	}
	HANDLE hMapping=CreateFileMapping(hFile,NULL,PAGE_READWRITE,0,0,NULL);  //创建内存映射对象
	if(INVALID_HANDLE_VALUE == hMapping)
	{
		msg("CreateFileMapping :%08X ErrorCode:%d\n", hMapping, GetLastError());
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
		if(offset > 0 && !IsFilterTable(segname))
		{
			//msg("offset:%X  segname:%s EA:%08X, nSize: %X\n", offset, segname, curseg->startEA, nSize);
			unsigned char *lpMem = (unsigned char*)malloc(nSize + 1);
			memset(lpMem, 0, nSize + 1);
			//if(get_many_bytes(curseg->startEA, lpMem, nSize))
			if(segReadBuf(curseg->startEA, lpMem, nSize))
			{
				SegWriteFile(pvFile, lpMem, nSize, offset);
			}
			//msg("lpMem:%X\n", lpMem);
			free(lpMem);
		}

		//	msg("Name:%s, StartEA:%08X, Offset:%08X, EndEA:%08X\n", segname, curseg->startEA, offset, curseg->endEA);


	}
	CloseHandle(hMapping);
//	msg("CloseHandle(hMapping)\n");
	UnmapViewOfFile(pvFile);
//	msg("UnmapViewOfFile(pvFile);\n");
	CloseHandle(hFile);
	msg("文件同步成功!\n");
	return;
}
HWND CreateButton(DWORD dwStyle, LPCTSTR pTitle, HWND hParent, INT x, INT y, INT width, INT height, WORD wID) {
// 	HWND hTmp;
// 	if (hTmp =  CreateWindowEx(NULL, WC_BUTTON, pTitle, BS_NOTIFY|WS_TABSTOP|WS_CHILD|WS_VISIBLE| dwStyle, x, y, width, height, hParent, (HMENU)wID, g_hinstPlugin, NULL))
// 		SetFont(hTmp);
// 
// 	return hTmp;
	return CreateWindowEx(NULL, WC_BUTTON, pTitle, BS_NOTIFY|WS_TABSTOP|WS_CHILD|WS_VISIBLE| dwStyle, x, y, width, height, hParent, (HMENU)wID, g_hinstPlugin, NULL);
}
void Main_OnSize(HWND hwnd, UINT state, int cx, int cy)
{
	RECT rcOk = {0};
	GetWindowRect(GetDlgItem(hwnd,IDOK),&rcOk);

	RECT rcLb = {0};
	GetWindowRect(GetDlgItem(hwnd,IDC_LIST_SEG),&rcLb);

	MoveWindow(GetDlgItem(hwnd,IDC_LIST_SEG),0,0,
		cx, cy - (HEIGHT(rcOk) + 2),TRUE);
	MoveWindow(GetDlgItem(hwnd,IDOK), cx - WIDTH(rcOk),
		cy - HEIGHT(rcOk), WIDTH(rcOk),HEIGHT(rcOk),TRUE);

	//Refresh label
	MoveWindow(GetDlgItem(hwnd,IDC_LIST_SEG), 1,
		cy - HEIGHT(rcOk) + 1, cx - WIDTH(rcOk) - 4, HEIGHT(rcOk) - 2,TRUE);
	Refresh(GetDlgItem(hwnd,IDC_LIST_SEG)); //And label contents

}
HBRUSH SetColor(HDC hdc, COLORREF TxtColr, COLORREF BkColr)
{
	static HBRUSH ReUsableBrush;
	DeleteObject(ReUsableBrush);
	ReUsableBrush = CreateSolidBrush(BkColr);
	SetTextColor(hdc, TxtColr);
	SetBkColor(hdc, BkColr);
	return ReUsableBrush;
}

HBRUSH Main_OnCtlColorListbox(HWND hwnd, HDC hdc, HWND hwndChild, int type)
{
	return SetColor(hdc, GetSysColor(COLOR_BTNTEXT), GetSysColor(COLOR_BTNFACE));
}
void Main_OnCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify)
{
	if(id < 0x1000)
	{
		//MessageBox(NULL, szBuf, NULL, 0);
		if(BST_CHECKED == IsDlgButtonChecked(hwnd, id) )
		{
			CheckDlgButton(hwnd,   id,   BST_UNCHECKED   );
		}
		else if(BST_UNCHECKED == IsDlgButtonChecked(hwnd, id))
		{
			CheckDlgButton(hwnd,   id,   BST_CHECKED   );
		}
	}
	switch (id)  
	{  
		//相加

	case IDC_DLGSEG_OK:
		//Ssys_Add(hwnd);			//相加1
		break;
	case IDC_DLGSIG_CANCEL:
		break;
	case IDC_LIST_SEG:
		{
			switch(codeNotify)
			{
			case LBCN_ITEMCHECK:
				msg("ItemCheck");
				break;
			case LBN_SELCHANGE:
				msg("SelectedIndexChanged");
				break;
			}
		}
		break;
	}
}

LRESULT CALLBACK ApplyDlgProc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) 
{
	static HWND hListBox=0;
	switch (message)  
	{  
		HANDLE_MSG (hwnd, WM_SIZE, Main_OnSize);
		HANDLE_MSG (hwnd, WM_CTLCOLORLISTBOX, Main_OnCtlColorListbox);
		HANDLE_MSG (hwnd, WM_COMMAND, Main_OnCommand);
	case WM_INITDIALOG:  
		{
			int i = 0;
			for(i = 0; i < 3; i++)
			{
				CreateButton(BS_CHECKBOX, "CheckBox", hwnd, 50, 120 + i * 30, 10 * strlen("CheckBox"), 24, 0x100 + i);
				//	CreateButton(BS_CHECKBOX, "CheckBox", hwnd, 50, 150, 50, 24, 3);
			}
			INITCOMMONCONTROLSEX icc;
			WNDCLASSEX wcx;


			icc.dwSize = sizeof(icc);
			icc.dwICC = ICC_WIN95_CLASSES;
			InitCommonControlsEx(&icc);
			InitCheckedListBox(g_hinstPlugin);
// 			hListBox = CreateWindow("ListBox",
// 				NULL,
// 				WS_VISIBLE |WS_CHILDWINDOW |WS_EX_CLIENTEDGE |WS_CHILD|WS_VSCROLL | WS_TABSTOP | LBS_SORT| LBS_NOTIFY | LBS_OWNERDRAWFIXED | LBS_HASSTRINGS,
// 				// LVS_REPORT|WS_CHILD|WS_VISIBLE,
// 				230, 20, 60, 80, 
// 				hwnd, (HMENU)IDC_LIST_SEG, 
// 				(HINSTANCE) GetWindowLong(hwnd, GWL_HINSTANCE), 
// 				NULL);
			hListBox = GetDlgItem(hwnd, IDC_LIST_SEGMEN);
			//ShowWindow(hListBox,SW_SHOW);
			//SendMessage(hListBox,LB_ADDSTRING ,0,(LPARAM)"你好");
			//SendMessage(hListBox,LB_ADDSTRING ,0,(LPARAM)"我好");
			//SendMessage(hListBox,LB_ADDSTRING ,0,(LPARAM)"他好");
			CheckedListBox_SetFlatStyleChecks(hListBox, TRUE);
			ListBox_AddString(hListBox,"Ford");
			ListBox_AddString(hListBox,"Toyota");
			ListBox_AddString(hListBox,"Chevy");
			//
			//return hListBox;
			break;
		}
		//Dlg_Init(hwnd);
// 	case WM_CTLCOLORLISTBOX://ODT_LISTBOX
// 		if((UINT) wParam==0x2000)
// 		{
// 			LPMEASUREITEMSTRUCT lpmis = (LPMEASUREITEMSTRUCT) lParam;
// 			lpmis->itemWidth=400;
// 			lpmis->itemHeight=22;
// 		}
// 		break;
// 	case WM_DRAWITEM:
// 
// 		if((UINT) wParam==0x2000)
// 		{
// 			LPDRAWITEMSTRUCT pDI=(LPDRAWITEMSTRUCT) lParam;
// 			HBRUSH brsh=CreateSolidBrush(RGB(255-30*pDI->itemID, 128+40*pDI->itemID, 128+40*pDI->itemID));//yellow
// 			FillRect(pDI->hDC,&pDI->rcItem,brsh);
// 			DeleteObject(brsh);
// 			// text 
// 			SetBkMode(pDI->hDC,TRANSPARENT);
// 			char szText[260];
// 			SendMessage(hListBox,LB_GETTEXT,pDI->itemID,(LPARAM)szText);
// 			const DWORD dwStyle = DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX | DT_END_ELLIPSIS;
// 			DrawText(pDI->hDC, szText, strlen(szText), &pDI->rcItem, dwStyle);
// 		}
// 		break;
// 	case WM_COMMAND:       
// 		{  
// 			if(wParam < 0x1000)
// 			{
// 				char szBuf[256] = {0};
// 				sprintf(szBuf, "wp:%X lp:%X\n", wParam, lParam);
// 				msg(szBuf);
// 				//MessageBox(NULL, szBuf, NULL, 0);
// 				if(BST_CHECKED == IsDlgButtonChecked(hwnd, LOWORD(wParam)) )
// 				{
// 					CheckDlgButton(hwnd,   LOWORD(wParam),   BST_UNCHECKED   );
// 				}
// 				else if(BST_UNCHECKED == IsDlgButtonChecked(hwnd, LOWORD(wParam)))
// 				{
// 					CheckDlgButton(hwnd,   LOWORD(wParam),   BST_CHECKED   );
// 				}
// 			}
// 			switch (LOWORD(wParam))  
// 			{  
// 				//相加
// 			
// 			case IDC_DLGSEG_OK:
// 				//Ssys_Add(hwnd);			//相加1
// 				break;
// 			case IDC_DLGSIG_CANCEL:
// 				break;
// 			}
// 
// 		}  
// 		break;

	case WM_CLOSE:  
		EndDialog(hwnd,IDOK);
		break;  
	}  
	return FALSE ; 
}