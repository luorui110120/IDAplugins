#include "DlgMain.h"


HINSTANCE g_hInstance;
char g_szReleasePath[256] = {0};

BOOL ReleaseRes(char* strFileName, WORD wResID, char* strFileType)
{
	DWORD   dwWrite=0;          

	// 创建文件    
	HANDLE  hFile = CreateFile(strFileName, GENERIC_WRITE,FILE_SHARE_WRITE,NULL,    
		CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);    
	if ( hFile == INVALID_HANDLE_VALUE )    
	{    
		return FALSE;    
	}    

	// 查找资源文件中、加载资源到内存、得到资源大小    
	HRSRC   hrsc =  FindResource(g_hInstance, MAKEINTRESOURCE(wResID), strFileType);    
	HGLOBAL hG = LoadResource(g_hInstance, hrsc);    
	DWORD   dwSize = SizeofResource( g_hInstance,  hrsc);    

	// 写入文件    
	WriteFile(hFile,hG,dwSize,&dwWrite,NULL);       
	//GlobalFree(hG);
	CloseHandle( hFile );    
	 return TRUE;
}
int __stdcall IDAP_init(void)
{
	//在这里做一些校验，以确保您的插件是被用在合适的环境里。
	//返回PLUGIN_SKIP 、PLUGIN_OK或者PLUGIN_KEEP，具体含义见后文
	char szTmpBuf[256] = {0};
	if(PLFM_ARM != ph.id)
	{
		return PLUGIN_SKIP;
	}
	GetModuleFileName(g_hInstance, szTmpBuf, sizeof(szTmpBuf));
	GetShortPathName(szTmpBuf, g_szReleasePath, sizeof(g_szReleasePath));
	*strrchr(g_szReleasePath, '\\') = 0;
#ifdef __EA64__
	strcat(g_szReleasePath, "\\as64.exe");
#else
	strcat(g_szReleasePath, "\\as.exe");
#endif
	if(INVALID_FILE_ATTRIBUTES == GetFileAttributes(g_szReleasePath))
	{
#ifdef __EA64__
		ReleaseRes(g_szReleasePath, IDR_AS64_EXE, "EXE");
#else
		ReleaseRes(g_szReleasePath, IDR_AS_EXE, "EXE");
#endif
	}
//	MessageBox(NULL, g_szReleasePath, NULL, 0);
	return PLUGIN_OK;
}
void __stdcall IDAP_term(void)
{
	//当结束插件时，一般您可以在此添加一点任务清理的代码。
	return;
}

//按钮事件的响应函数
void idaapi button_func(TView *fields[], int code)
{
	msg("The button was pressed!\n");
}

// 插件可以从plugins.cfg文件中，被传进一个整型参数。
// 当按下不同的热键或者菜单时，您需要一个插件做不同
// 的事情时，这非常有用。
void __stdcall IDAP_run(int arg)
{
	MSG msg;
	HWND hMainDlg = NULL;
	if( (hMainDlg = FindWindow("#32770","ARM_Code　")) == NULL)
	{
		EnumWindows(EnumWindowsProc,0);
		hMainDlg = CreateDialog(g_hInstance, (LPCTSTR)IDD_DIALOG1, NULL,(DLGPROC)Main_Proc);

		ShowWindow(hMainDlg, SW_SHOWNA);
	}
	else
	{
		SetForegroundWindow(hMainDlg);
	}

// 	while (GetMessage(&msg, NULL, 0, 0))
// 	{
// 		TranslateMessage(&msg);
// 		if(msg.message == WM_CLOSE || msg.message == WM_DESTROY)
// 		{
// 			Main_OnClose(hMainDlg);
// 			break;
// 		}
// 		
// 		DispatchMessage(&msg);
// 		
// 	}
	return;
}

BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if(ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(g_hInstance = hModule);
	}
	return (TRUE);
}
// 下面的这些字符都是可以自行设定的
char IDAP_comment[] = "Comment of my first ida plugin MyFind. By 空道";
char IDAP_help[] = "http://bbs.chinapyg.com/";
// 在Edit->Plugins 菜单中，插件的现实名称，
// 它能被用户的plugins.cfg文件改写
char IDAP_name[] = "MyPatchARMCode";
// 启动插件的热键，纯字符的定义，比较易懂
char IDAP_hotkey[] = "shift-SPACE";
// 所有PLUGIN对象导出的重要属性。
//这个是一定要定义的，原因参考后文
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION, // IDA version plug-in is written for
	0, // Flags (see below)
	IDAP_init, // Initialisation function
	IDAP_term, // Clean-up function
	IDAP_run, // Main plug-in body
	IDAP_comment, // Comment –unused
	IDAP_help, // As above –unused
	IDAP_name, // Plug-in name shown in
	// Edit->Plugins menu
	IDAP_hotkey // Hot key to run the plug-in
};