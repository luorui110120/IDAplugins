
#include "DlgMain.h"


HINSTANCE g_hInstance;
int __stdcall IDAP_init(void)
{
	//在这里做一些校验，以确保您的插件是被用在合适的环境里。
	//返回PLUGIN_SKIP 、PLUGIN_OK或者PLUGIN_KEEP，具体含义见后文
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


void __stdcall IDAP_run(int arg)
{

	HWND hMainDlg = NULL;
	if(NULL == (hMainDlg=FindWindow("#32770", "Find Code")) )
	{
		EnumWindows(EnumWindowsProc,0);
		hMainDlg = CreateDialog(g_hInstance, (LPCTSTR)IDD_DIALOG_FINDCODE, NULL,(DLGPROC)Main_Proc);
		if(NULL == hMainDlg)
		{
			msg("hMainDlg NULL 0x%X\n",GetLastError());
		}
		else
		{
			ShowWindow(hMainDlg, SW_SHOWNA);
		}
	}
	else
	{
		POINT p;
		GetCursorPos(&p);
		RECT rect;
		GetWindowRect(hMainDlg,&rect);   //rect保存窗口大小
		MoveWindow(hMainDlg, p.x, p.y, rect.right - rect.left, rect.bottom - rect.top, TRUE);
		SwitchToThisWindow(hMainDlg, TRUE);
	}
	
	

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
char IDAP_comment[] = "Comment of my first ida plugin. By: 空道.";
char IDAP_help[] = "http://bbs.chinapyg.com/";
// 在Edit->Plugins 菜单中，插件的现实名称，
// 它能被用户的plugins.cfg文件改写
char IDAP_name[] = "KDFindCode";
// 启动插件的热键，纯字符的定义，比较易懂
char IDAP_hotkey[] = "Shift-Alt-t";
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