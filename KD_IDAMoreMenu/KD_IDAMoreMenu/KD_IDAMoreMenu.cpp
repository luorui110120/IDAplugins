#include <windows.h>
#include <Shlwapi.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <search.hpp>
#include <kernwin.hpp>
#include <stdio.h>
#include <vector>
#include <string>
#include "KD_IDAMoreMenu.h"
#include "ASCIIDlg.h"
#include "CalcDlg.h"
#include "ApplyDlg.h"
#include "JNIEnvList.h"
#include <Commctrl.h>

#define WM_JNIENVLIST WM_USER+2
#define WM_SAVE_IDC WM_USER+3
#define WM_REPAIR_ELF WM_USER+4
#define WM_INITTABLIELIST WM_USER+5




using namespace std;

#pragma comment(lib,"ida.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Comctl32.lib");
//#define  MSG msg
#define  USHORT ushort
HWND g_hwndMain ;
HWND g_hwndSub;


HINSTANCE g_hinstPlugin;

WNDPROC wpsubClass; 
//功能按钮的文件名
char	szToolBarBtnName[FUNCBTNNUM][20]={
	"TARGET.bmp",
	"STRING.bmp",
	"Script.bmp",
	"CLAC.bmp",
	"EXPORT.bmp",
	"JNIENV.bmp",
	"APPLY.bmp",
	"CLOSE.bmp",
	
};
WORD	g_ToolBarBtnResID[FUNCBTNNUM]=
{
	IDB_BITMAP_TARGET,
	IDB_BITMAP_STRING,
	IDB_BITMAP_ACSII,
	IDB_BITMAP_CLAC,
	IDB_BITMAP_EXPORT,
	IDB_BITMAP_JNIENV,
	IDB_BITMAP_INITTABLE,
	IDB_BITMAP_APPLY,
	IDB_BITMAP_REPAIR,
	IDB_BITMAP_CLOSE,
};
//////////////////////////////////////////
extern int repairelf(char *lpFilePath);
extern int ShowInitTableList();
/////////////////////////////////////////
BOOL MyCreateWindows();
///////////////////////////////////////
DWORD WINAPI DumpBaseIdcProc(LPVOID lpParameter)
{

// 	SetForegroundWindow(g_hwndMain);
// 	keybd_event(VK_MENU, 0, 0, 0); 
// 	keybd_event('F', 0, 0, 0); 
// 	keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, 0); 
// 	keybd_event(VK_RETURN, 0, KEYEVENTF_KEYUP, 0); 
// 	keybd_event('P', 0, 0, 0); 
// 	keybd_event('P', 0, KEYEVENTF_KEYUP, 0); 
// 	HWND hwnd2 = FindWindow("QPopup", "idaq");
// 	RECT rect;
// 	int i = 0;;
// 	while(!hwnd2 || !IsWindowVisible(hwnd2) || !GetClientRect(hwnd2, &rect) || rect.right != 262 || rect.bottom!= 235 && i < 20)
// 	{
// 		hwnd2 = FindWindowEx(NULL, hwnd2, "QPopup", "idaq");
// 		Sleep(10);
// 		i++;
// 	}
// 	if(i < 20)
// 	{
// 		//MessageBox(NULL, "zhaodao", 0, 0);
// 		keybd_event('U', 0, 0, 0); 
// 		keybd_event('U', 0, KEYEVENTF_KEYUP, 0); 
// 	}
	int i;
	segment_t *curseg;
	ea_t startaddr, endaddr;
	char *lpSavePath;
	FILE *f = NULL;
	int seg_qty = get_segm_qty();
	if(seg_qty > 0)
	{
		curseg = getnseg(0);
		startaddr = curseg->startEA;
		endaddr = curseg->endEA;
	}
	else
	{
		msg("get seg error!\n");
		return 0;
	}
	for(i=1 ; i < seg_qty; i++)
	{
		curseg = getnseg(i);
		if(startaddr > curseg->startEA)
		{
			startaddr = curseg->startEA;
		}
		if(endaddr < curseg->endEA)
		{
			endaddr = curseg->endEA;
		}
	}
	char szFilePath[256 * 2] = {0};
	strncpy(szFilePath, database_idb, 256);
	char *lpTmpBuf = strrchr(szFilePath, '\\') + 1;
	*lpTmpBuf = 0;
	get_root_filename(lpTmpBuf, 256);
	if(strrchr(lpTmpBuf, '.'))
	{
		*strrchr(lpTmpBuf, '.') = 0;
	}
	strcat(lpTmpBuf, ".idc");
	msg("startAddr:%08X  endAddr:%08X\n", startaddr, endaddr);
	lpSavePath = askfile_cv(1, szFilePath, "SaveIDC", 0);
	if(lpSavePath == NULL)
	{
		msg("取消了 IDC Save\n");
		return 0;
	}
	if( (f = fopen(lpSavePath, "r")) != NULL)
	{
		fclose(f);
		if( askyn_c(1, "是否覆盖文件") <= 0)
		{
			msg("取消覆盖 !\n");
			return 0;
		}
	}
	//	msg("Name:%s, StartEA:%08X, Offset:%08X, EndEA:%08X\n", segname, curseg->startEA, offset, curseg->endEA);

	// Open the output file
	msg("Save IDC Path:%s\n", lpSavePath);
	f = qfopen(lpSavePath, "w");
	if(f != NULL)
	{
		// Generate an IDC output file
		gen_file(OFILE_IDC, f, startaddr, endaddr, 0);

		// Close the output file
		qfclose(f);
	}
	else
	{
		warning("保存IDC 失败!\n");
		return 0;
	}
	return 0;
}
//处理工具和断点的消息

LRESULT CALLBACK SubWindowProc(
							  HWND hwnd,      // handle to window
							  UINT uMsg,      // message identifier
							  WPARAM wParam,  // first message parameter
							  LPARAM lParam   // second message parameter
							  )
{
	//加载工具栏   //把按钮画到工具栏上
	LRESULT iRet = DefWindowProc(hwnd,uMsg,wParam,lParam);
	if(uMsg ==WM_PAINT)
	{
		for (int i=0;i<TOOLBARNUM;i++)
		{
			//加载工具栏
			DrawToolBar(hwnd,TOOLBARPOS+(i*0x14),hBitmap[i],hToolBarColor[1],hToolBarColor[0]);
		}
		return 0;
//		goto returns;

	}
//	LRESULT iRet = DefWindowProc(hwnd,uMsg,wParam,lParam);
	//响应画上去按钮的左键按下事件
	if (uMsg == WM_LBUTTONDOWN)
	{

		//取鼠标按下的位置	
		int xpos = LOWORD(lParam);
		int ypos = lParam >> 16;
		//根据位置获取当前的按钮
		nDownNum = GetButtonPos(xpos,ypos);
		if (nDownNum !=(-1))
		{
			DrawToolBar(hwnd,TOOLBARPOS+(nDownNum*0x14),hBitmap[nDownNum],hToolBarColor[0],hToolBarColor[1],0);
			bDownFlag = TRUE;
		}
		goto returns;
	}
	//响应画上去按钮的左键按下事件
	if (uMsg == WM_LBUTTONUP)
	{
		//取鼠标按下的位置
		SendMessageA(hwnd,WM_PAINT,NULL,NULL);
		if (bDownFlag)
		{
// 			char szBuf[256] = {0};
// 			sprintf(szBuf, "%d", nDownNum);
// 			if(nDownNum >= 0)
// 			{
// 				MessageBox(hwnd, szBuf, szBuf, 0);
// 			}
			
			switch(nDownNum)
			{
				//打开文件路径
			case 0:
				{
					char szTmpBuf[MAX_PATH] = {0};
					//RootNode.valstr(szTmpBuf, MAX_PATH);
					strncpy(szTmpBuf, database_idb, MAX_PATH);
					if(szTmpBuf[0] > 0)
					{
						*strrchr(szTmpBuf, '\\') = 0;
						SHELLEXECUTEINFO shinfo;
						shinfo.cbSize=sizeof(SHELLEXECUTEINFO);
						shinfo.fMask=SEE_MASK_NOCLOSEPROCESS;
						shinfo.hwnd=NULL;
						shinfo.lpVerb=NULL;
						shinfo.lpFile="explorer.exe";
						shinfo.lpParameters=szTmpBuf;
						shinfo.lpDirectory=NULL;
						shinfo.nShow=SW_SHOW;
						shinfo.hInstApp=NULL;
						ShellExecuteEx(&shinfo);
					}
					
					break;
				}
			case 1:
				{
					SetForegroundWindow(g_hwndMain);
					keybd_event(VK_SHIFT, 0, 0, 0); 
					keybd_event(VK_F12, 0, 0, 0); 
					keybd_event(VK_SHIFT, 0, KEYEVENTF_KEYUP, 0); 
					keybd_event(VK_F12, 0, KEYEVENTF_KEYUP, 0); 
					break;
				}
			case 2:
				{
					OpenProcDlg(IDD_DLGASCII,(DLGPROC)AsciiDlgProc);
					break;
				}
			case 3:
				{
					OpenProcDlg(IDD_DLGCALC,(DLGPROC)CalcDlgProc);
					break;
				}
			case 4:
				{
				//	CreateThread(NULL,0,DumpBaseIdcProc,NULL,0,NULL);
				//	DumpBaseIdcProc(NULL);
				//	SendMessage(g_hwndMain, WM_PAINT, 0, 0);


				//	SendMessage(g_hwndMain, WM_SAVE_IDC, NULL, NULL);

					////使用下面这种方式需要 配置 快捷键  打开 cfg/idagui.cfg 文件 找到  DumpDatabase  然后配置快捷键 "shif-alt-f12"
					SetForegroundWindow(g_hwndMain);
					keybd_event(VK_MENU, 0, 0, 0); 
					keybd_event(VK_SHIFT, 0, 0, 0); 
					keybd_event(VK_F12, 0, 0, 0); 
					keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, 0); 
					keybd_event(VK_SHIFT, 0, KEYEVENTF_KEYUP, 0);
					keybd_event(VK_F12, 0, KEYEVENTF_KEYUP, 0); 
					break;
				}
			case 5:
				{
// 					SetForegroundWindow(g_hwndMain);
// 					keybd_event(VK_SHIFT, 0, 0, 0); 
// 					keybd_event(VK_F7, 0, 0, 0); 
// 					keybd_event(VK_SHIFT, 0, KEYEVENTF_KEYUP, 0); 
// 					keybd_event(VK_F7, 0, KEYEVENTF_KEYUP, 0); 
					//CreateThread(NULL,0,ShowJNIEnvListThread,NULL,0,NULL);
					SendMessage(g_hwndMain, WM_JNIENVLIST, NULL, NULL);
					//ShowJNIEnvList();
					break;
				}
			case 6:
				{
					SendMessage(g_hwndMain, WM_INITTABLIELIST, NULL, NULL);
					
					break;
				}
			case 7:
				{
					//Apply_patches();		//将ida数据库的段的修改同步到文件上
					//OpenProcDlg(IDD_DLGSEG,(DLGPROC)ApplyDlgProc);
					if(get_segm_qty() > 0)
					{
						ApplyWinMain(g_hinstPlugin);
					}
					else
					{
						msg("Error! 不存在区段\n");
					}
					break;
				}
			case 8:
				{
					SendMessage(g_hwndMain, WM_REPAIR_ELF, NULL, NULL);
					
					break;
				}
			default:
				{
					SetForegroundWindow(g_hwndMain);
					keybd_event(VK_MENU, 0, 0, 0); 
					keybd_event('F', 0, 0, 0); 
					keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, 0); 
					keybd_event(VK_RETURN, 0, KEYEVENTF_KEYUP, 0); 
					keybd_event('C', 0, 0, 0); 
					keybd_event('C', 0, KEYEVENTF_KEYUP, 0); 
					break;
				}
			
			}
			bDownFlag = FALSE;
			nDownNum = -1;
		}
		goto returns;
	}
	if (uMsg ==WM_MOUSEMOVE )
	{
		static int sxpos = 0, sypos = 0;
		int xpos = LOWORD(lParam);
		int ypos = lParam >> 16;
		int ntmp = GetButtonPos(xpos,ypos);
		if(sxpos == xpos && ypos == sypos)
		{
			ntmp = -1;
		}
		else
		{
			sxpos = xpos;
			sypos = ypos;
		}
		if (ntmp != (-1))
		{
			switch(ntmp)
			{
			case 0:
				ShowToolTip(hwnd, "打开数据库所在文件夹");
				break;
			case 1:
				ShowToolTip(hwnd, "打开String窗口");
				break;
			case 2:
				ShowToolTip(hwnd,"显示ACSII表");
				break;
			case 3:
				ShowToolTip(hwnd,"打开 计算器");
				break;
			case 4:
				ShowToolTip(hwnd,"将数据导出为IDC");
				break;
			case 5:
			//	ShowToolTip(hwnd,"查看Segments");
				ShowToolTip(hwnd,"打开 JNIEnv函数表");
				break;
			case 6:
				//	ShowToolTip(hwnd,"查看Segments");
				ShowToolTip(hwnd,"打开 中断表");
				break;
			case 7:
				ShowToolTip(hwnd,"将数据库的修改同步到文件上");
				break;
			case 8:
				ShowToolTip(hwnd,"修复ELF文件头");
				break;
			default:
				ShowToolTip(hwnd,"关闭当前数据库");
				break;
			}
		}
		goto returns;
	}
	
	if(uMsg == WM_CLOSE)
	{
		ExitThread(0);
	}
	
returns:
	return iRet;
}
HBITMAP BufferToHBITMAP(HWND hwnd, WORD wResID) 
{ 
	HBITMAP                hShowBMP; 
	LPSTR                hDIB,lpBuffer; 
	LPVOID                lpDIBBits; 
	BITMAPFILEHEADER    bmfHeader; 
	DWORD                bmfHeaderLen; 
	////////////////////////////////////
	HRSRC hrsc = FindResource(g_hinstPlugin, MAKEINTRESOURCE(wResID), RT_BITMAP);
	if(hrsc == NULL)
	{
		MessageBox(NULL,"123",NULL,0);
		return NULL;
	}
	lpBuffer = (LPSTR)LoadResource(g_hinstPlugin, hrsc);    
	DWORD   dwSize = SizeofResource( g_hinstPlugin,  hrsc);   
	//////////////////////////////////////
	bmfHeaderLen = sizeof(bmfHeader); 
	strncpy((LPSTR)&bmfHeader,(LPSTR)lpBuffer,bmfHeaderLen); 
	if (bmfHeader.bfType != (*(WORD*)"BM")) return NULL; 
	hDIB = lpBuffer + bmfHeaderLen; 
	BITMAPINFOHEADER &bmiHeader = *(LPBITMAPINFOHEADER)hDIB ; 
	BITMAPINFO &bmInfo = *(LPBITMAPINFO)hDIB ; 
	lpDIBBits=(lpBuffer)+((BITMAPFILEHEADER *)lpBuffer)->bfOffBits; 
	//	CClientDC dc(this); 
	hShowBMP = CreateDIBitmap(GetDC(hwnd),&bmiHeader,CBM_INIT,lpDIBBits,
		&bmInfo,DIB_RGB_COLORS); 
	FreeResource(lpBuffer);
	return hShowBMP; 
} 
void  ShowToolTip(HWND hwnd, char *lpBuf)
{


	// struct specifying control classes to register

	INITCOMMONCONTROLSEX iccex;
	static HWND hwndTT = NULL; // handle to the ToolTip control
	// struct specifying info about tool in ToolTip control
	TOOLINFO ti;
	unsigned int uid = 0; // for ti initialization

	RECT rect; // for client area coordinates

	DWORD dwStringID[] = {106, 109, 107, 108};

	TCHAR szInfo[MAX_PATH];
	memset(szInfo, 0, MAX_PATH);
	HINSTANCE hThisInstance = (HINSTANCE)GetModuleHandle(0);

	if(hwndTT)
	{
		GetClientRect (hwnd, &rect);
		ti.cbSize = sizeof(TOOLINFO);
		ti.uFlags = TTF_SUBCLASS;
		ti.hwnd = hwnd;
		ti.hinst = hThisInstance;
		ti.uId = uid;
		ti.lpszText = lpBuf;
		// ToolTip control will cover the whole window
		ti.rect.left = rect.left;
		ti.rect.top = rect.top;
		ti.rect.right = rect.right;
		ti.rect.bottom = rect.bottom;
		SendMessage(hwndTT, TTM_SETTOOLINFO, 0, (LPARAM) (LPTOOLINFO) &ti);
		//SendMessage(hwndTT,TTM_SETDELAYTIME,(WPARAM)(DWORD)TTDT_INITIAL,(LPARAM)(INT)MAKELONG(1000,0));

		return;
	}
	/* INITIALIZE COMMON CONTROLS */
	iccex.dwICC = ICC_TAB_CLASSES;
	iccex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	InitCommonControlsEx(&iccex);

	/* CREATE A TOOLTIP WINDOW */
	hwndTT = CreateWindowEx(WS_EX_TOPMOST,
		TOOLTIPS_CLASS,
		NULL,
		WS_POPUP|TTS_NOPREFIX|TTS_ALWAYSTIP,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		hwnd,
		NULL,
		hThisInstance,
		NULL
		);

	SetWindowPos(hwndTT,
		HWND_TOPMOST,
		0,
		0,
		0,
		0,
		SWP_NOMOVE|SWP_NOSIZE|SWP_NOACTIVATE);

	/* GET COORDINATES OF THE MAIN CLIENT AREA */
	GetClientRect (hwnd, &rect);

	/* INITIALIZE MEMBERS OF THE TOOLINFO STRUCTURE */
	ti.cbSize = sizeof(TOOLINFO);
	ti.uFlags = TTF_SUBCLASS;
	ti.hwnd = hwnd;
	ti.hinst = hThisInstance;
	ti.uId = uid;
	ti.lpszText = lpBuf;
	// ToolTip control will cover the whole window
	ti.rect.left = rect.left;
	ti.rect.top = rect.top;
	ti.rect.right = rect.right;
	ti.rect.bottom = rect.bottom;

	/* SEND AN ADDTOOL MESSAGE TO THE TOOLTIP CONTROL WINDOW */
	SendMessage(hwndTT, TTM_ADDTOOL, 0, (LPARAM) (LPTOOLINFO) &ti);
	//popup 5 seconds disappear
	SendMessage(hwndTT,TTM_SETDELAYTIME,(WPARAM)(DWORD)TTDT_AUTOPOP,(LPARAM)(INT)MAKELONG(5000,0));
	
}

BOOL MyCreateWindows()
{
	static MSG msg1;
	static HWND hWnd;
	char szTitle[]="Message";                                // The title bar text
	char szWindowClass[]="popMsg";                                // The title bar text
	static WNDCLASSEX wcex={0};
	wcex.cbSize = sizeof(WNDCLASSEX);        //WNDCLASSEX结构体大小
	wcex.style            = 0;    //位置改变时重绘
	wcex.lpfnWndProc    = (WNDPROC)SubWindowProc;            //消息处理函数
	wcex.hInstance        = 0;            //当前实例句柄
	wcex.hbrBackground    = (HBRUSH)COLOR_WINDOWFRAME;    //背景色
	wcex.lpszClassName    = szWindowClass;        //参窗口类名
	wcex.hIcon            =0;        //图标
	wcex.hCursor        =LoadCursor(NULL, IDC_ARROW);        //光标
	wcex.lpszMenuName    =0;        //菜单名称
	wcex.hIconSm        =0;        //最小化图标
//	RegisterClassEx(&wcex);            //注册窗口类
	if(!RegisterClassEx(&wcex)) //为程序窗口注册窗口类别
	{
		MessageBox(NULL,TEXT("This program requires Windows NT!"), "Title",MB_ICONERROR);
		return 0;
	}
	hWnd = CreateWindow(szWindowClass, szTitle, WS_CHILDWINDOW | WS_VISIBLE ,    //创建窗口
		690,0, 20 * MAXTOOLBARBTNNUM, 16, g_hwndMain, NULL, 0, NULL);



	g_hwndSub = hWnd;
	if (!hWnd){
		DWORD dwTmp = GetLastError();
		char szBuf[256] = {0};
		sprintf(szBuf, "%X",dwTmp);
		MessageBox(NULL, szBuf, NULL, NULL);
		return FALSE;
	}
	ShowToolTip(hWnd, "");
	ShowWindow(hWnd, SW_SHOW);
	UpdateWindow(hWnd);
//	MessageBox(NULL, "text", "Ttile", 0);

	while (GetMessage(&msg1, NULL, 0, 0))     // 消息循环:
	{
		TranslateMessage(&msg1);        //转化虚拟按键到字符消息
		DispatchMessage(&msg1);        //分派消息调用回调函数
	}
	
	return TRUE;
}
DWORD WINAPI fun1Proc(LPVOID lpParameter)
{
	HWND hwnd = FindWindowEx(g_hwndMain, NULL,"popMsg","Message");
	while(!hwnd && !IsWindowVisible(g_hwndMain))
	{
		
		MyCreateWindows();
		
	}
	return 0;
}
LRESULT CALLBACK MainWindowProc(
								HWND hwnd,      // handle to window
								UINT uMsg,      // message identifier
								WPARAM wParam,  // first message parameter
								LPARAM lParam   // second message parameter
								)
{
	static int nOffsetHOTKEY = 0;
	LRESULT iRet = 0;
	if(uMsg == WM_DESTROY)
	{
	//	iRet = CallWindowProc(wpsubClass, hwnd, uMsg, wParam, lParam);
		HWND hwndSub = FindWindowEx(g_hwndMain, NULL,"popMsg","Message");
		if(hwndSub)
		{
			SetWindowLong(g_hwndMain, GWL_WNDPROC, (LONG) wpsubClass);
			SendMessage(hwndSub, WM_CLOSE, 0, 0);
			PostMessage(g_hwndMain, uMsg, 0, 0);
		}
	}
	else if(uMsg == WM_CLOSE)
	{
		char szTitle[256] = {0};
		HWND hwndSub = FindWindowEx(g_hwndMain, NULL,"popMsg","Message");
		GetWindowText(g_hwndMain, szTitle, 256);
		if(hwndSub && memcmp(szTitle, "IDA -", strlen("IDA -")))
		{
			SetWindowLong(g_hwndMain, GWL_WNDPROC, (LONG) wpsubClass);
			SendMessage(hwndSub, WM_CLOSE, 0, 0);
			PostMessage(g_hwndMain, uMsg, 0, 0);
		}
		else
		{
			iRet = CallWindowProc(wpsubClass, hwnd, uMsg, wParam, lParam);
		}
	}
	else if(uMsg == WM_HOTKEY)		//处理快捷键
	{
		iRet = CallWindowProc(wpsubClass, hwnd, uMsg, wParam, lParam);
// 		if (wParam==0xC001 )
// 		{
// 			HWND hwndTmp = GetForegroundWindow();
// 			char szBuf[256] = {0};
// 			GetClassName(hwndTmp, szBuf,256);
// 			if(strcmp("QWidget", szBuf) == 0)
// 			{
// 				PostMessage(hwndTmp, WM_JUMP_OFFSET, 0, 0);
// 				return 0;
// 			}
// 			else
// 			{
// 				iRet = CallWindowProc(wpsubClass, hwnd, uMsg, wParam, lParam);
// 			}
// 		//	msg("激活快捷键");
// 		//	SubWindowProc(g_hwndSub, WM_LBUTTONDOWN, 1, 0x000C0020);
// 		//	SubWindowProc(g_hwndSub, WM_LBUTTONUP, 0, 0x000C0020);
// 			
// 		}
// 		else
// 		{
// 			iRet = CallWindowProc(wpsubClass, hwnd, uMsg, wParam, lParam);
// 		}
	}
 	else if(uMsg == WM_KEYDOWN)
 	{
// 		msg("WM_KEYDOWN: %X,   nOffsetHOTKEY:%d\n", wParam, nOffsetHOTKEY);
//  		if(wParam == VK_MENU || wParam == VK_SHIFT || wParam == 'G' || wParam == 'g')
//  		{
//  			nOffsetHOTKEY++;
//  			if(nOffsetHOTKEY == 3)
//  			{
//  				ea_t nOffsetAddr = get_fileregion_offset(get_screen_ea());
//  				static char *dialog =			//给窗口布局
//  					"STARTITEM 0\n"			//让第一项获得焦点
//  					"JUMP Offset \n\n"
//  					"<#数据地址 0x#Offset  :M:9:16::>\n";
//  				if(AskUsingForm_c(dialog, &nOffsetAddr) == 1)
//  				{
//  					jumpto(get_fileregion_ea(nOffsetAddr));
//  				}
//  				return 0;
//  			}
//  		}
 		iRet = CallWindowProc(wpsubClass, hwnd, uMsg, wParam, lParam);
 	}
 	else if(uMsg == WM_KEYUP)
 	{
 //		msg("WM_KEYUP: %X,  nOffsetHOTKEY:%d\n", wParam, nOffsetHOTKEY);
//  		if(wParam == VK_MENU || wParam == VK_SHIFT || wParam == 'G' || wParam == 'g')
//  		{
//  			nOffsetHOTKEY--;
//  		}
 		iRet = CallWindowProc(wpsubClass, hwnd, uMsg, wParam, lParam);
 	}
	else if(uMsg == WM_JNIENVLIST)
	{
		ShowJNIEnvList();
	}
	else if(uMsg == WM_INITTABLIELIST)
	{
		ShowInitTableList();
	}
	else if(uMsg == WM_REPAIR_ELF)
	{
		char *lpPath = askfile_cv(0, "*", "RepairELF", 0);
		if(lpPath != NULL)
		{
			repairelf(lpPath);
		}
	}
	else if(uMsg == WM_SAVE_IDC)
	{
		DumpBaseIdcProc(NULL);
	}
	else
	{
		iRet = CallWindowProc(wpsubClass, hwnd, uMsg, wParam, lParam);
	}
	if(uMsg ==WM_PAINT)
	{
		static HANDLE hThread1= NULL;
		if(hThread1 == NULL)
		{
			hThread1 = CreateThread(NULL,0,fun1Proc,NULL,0,NULL);
		}
		
	}
	
	return iRet;
}
BOOL CALLBACK EnumWindowsProc(
	HWND hwnd,      // handle to parent window
	LPARAM lParam   // application-defined value
	)
{
	DWORD PID;
	BOOL  Result=TRUE;
	GetWindowThreadProcessId(hwnd,&PID);
	static DWORD LocalPid = 0;
	if(0 == LocalPid)
	{
		LocalPid = GetCurrentProcessId();
	}
	if (PID==LocalPid)
	{
		char szBuf[256] = {0};
		GetClassName(hwnd, szBuf,256);
		if(strcmp("QWidget", szBuf) == 0)
		{
			g_hwndMain = hwnd;//这个g_hwin在你的DLL里定义为一个全局的HWND,也是你想要的句柄
			//msg("g_hwndMain : %08X\n", g_hwndMain);
			Result = FALSE;
		}
	}
	return Result;
}
///////////////////////////////////
int __stdcall IDAP_init(void)
{
	int i = 0;
	//加载功能按钮图标文件
	for (i =0;i< MAXTOOLBARBTNNUM;i++)
	{
		hBitmap[i]= LoadBitmap(g_hinstPlugin, MAKEINTRESOURCE(g_ToolBarBtnResID[i]));
	}
//	TOOLBARPOS = GetPrivateProfileInt(g_CustomOptionSetion,"ToolBarPos",0x2E4,szODIni);
	if(0 == g_hwndMain)
	{
		EnumWindows(EnumWindowsProc,0);
		while( !g_hwndMain)
		{
			Sleep(100);
		}
		//g_hwndMain = FindWindow("QWidget", NULL);
		hToolBarColor[0]= GetStockObject(BLACK_PEN);//凸起来的样式
		hToolBarColor[1]= GetStockObject(WHITE_PEN);//凹下去的样式
		dwsumwight = TOOLBARPOS +((TOOLBARNUM-1)*20);
		//IsWindowVisible
		
		//RegisterHotKey(g_hwndMain,0xC001,MOD_SHIFT|MOD_ALT, 'G');	//注册快捷键
		wpsubClass = (WNDPROC) SetWindowLong(g_hwndMain, GWL_WNDPROC, (LONG) MainWindowProc); 
	}
	else
	{
		msg("Test No");
	}
	SendMessage(g_hwndMain, WM_PAINT, 0, 0);
	return PLUGIN_KEEP;
}
void __stdcall IDAP_term(void)
{
	//当结束插件时，一般您可以在此添加一点任务清理的代码。
	
//	PostMessage(g_hwndMain, WM_CLOSE, 0, 0);
//	SetWindowLong(g_hwndMain, GWL_WNDPROC, (LONG) wpsubClass);
	exit(0);
	return;
}



void __stdcall IDAP_run(int arg)
{
	msg("Test Run");


	return;
}
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID)
{
	if (DLL_PROCESS_ATTACH == fdwReason)
	{
		DisableThreadLibraryCalls(g_hinstPlugin = hinstDLL);
	}

	return TRUE;
}
// 下面的这些字符都是可以自行设定的
char IDAP_comment[] = "Comment of my first ida plugin. By 空道";
char IDAP_help[] = "www.chinapy.com";
// 在Edit->Plugins 菜单中，插件的现实名称，
// 它能被用户的plugins.cfg文件改写
char IDAP_name[] = "KD_IDAMoreMenu";
// 启动插件的热键，纯字符的定义，比较易懂
char IDAP_hotkey[] = "";
// 所有PLUGIN对象导出的重要属性。
//这个是一定要定义的，原因参考后文
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION, // IDA version plug-in is written for
	PLUGIN_FIX | PLUGIN_HIDE|PLUGIN_MOD, // Flags (see below)
	IDAP_init, // Initialisation function
	IDAP_term, // Clean-up function
	IDAP_run, // Main plug-in body
	IDAP_comment, // Comment –unused
	IDAP_help, // As above –unused
	IDAP_name, // Plug-in name shown in
	// Edit->Plugins menu
	IDAP_hotkey // Hot key to run the plug-in
};


/////////////////////////
//画工具栏
int DrawToolBar(HWND hWnd, int npos, HGDIOBJ hgdiobjtmp,HGDIOBJ a3, HGDIOBJ a4,int flag)
{
	HDC hOldDc;//v8
	HDC hOldDc2;//v9
	HGDIOBJ hGdiOBJ; //V11
	POINT pt;
	//int ntemp = npos+ 0x12;
	hOldDc = GetDC(hWnd);
	hGdiOBJ = SelectObject(hOldDc,hPen);
	MoveToEx(hOldDc,npos+ 0x12,2,&pt);
	LineTo(hOldDc,npos+ 0x12,0x12);
	//---------------------
	SelectObject(hOldDc,a3);
	MoveToEx(hOldDc,npos,0x12,&pt);
	LineTo(hOldDc,npos,2);
	LineTo(hOldDc,npos+0x12,2);
	//---------------------------
	SelectObject(hOldDc,a4);
	MoveToEx(hOldDc,npos,0x13,&pt);
	LineTo(hOldDc,npos+0x11,0x13);
	LineTo(hOldDc,npos+0x11,1);

	//-------------------------------
	hOldDc2=CreateCompatibleDC(hOldDc);
	SelectObject(hOldDc2,hgdiobjtmp);
	//这里
	BitBlt (hOldDc,npos+1,3,0x10,0x10,hOldDc2,flag,flag,SRCCOPY);

	DeleteObject(hOldDc2);
	SelectObject(hOldDc,hGdiOBJ);
	return ReleaseDC(hWnd,hOldDc);
}


int GetButtonPos(int x,int y)
{
	//判断是否自画的按钮
	if (x <TOOLBARPOS)
	{
		return -1;
	}
	int pos = TOOLBARPOS;
	int bRet = -1;

	for ( int i =0;i<TOOLBARNUM;i++)
	{
		if (x < pos +0x11+(i*0x14) && 
			x > pos+(i*0x14) &&
			y < 0x12 &&
			y > 2)
		{
			bRet = i;
			break;
		}

	}
	return bRet;
}
//打开对话框
void OpenProcDlg(UINT uid,DLGPROC proc)
{
	if (subhwnd!= NULL)
	{
		EndDialog(subhwnd,IDOK);
		subhwnd= NULL;
	}
	subhwnd=CreateDialogParam(g_hinstPlugin,MAKEINTRESOURCE(uid),g_hwndMain,proc,NULL);
	ShowWindow(subhwnd,SW_SHOW);
}