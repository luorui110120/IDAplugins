#include <windows.h>
#include <Shlwapi.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <stdio.h>



#pragma comment(lib,"ida.lib")
#define  MSG msg
#define  USHORT ushort


/////////////////////////////////////////////
int SnedClipData(char *lpBuf, int nlen)
{
	if( 0 == nlen || lpBuf == NULL)
	{
		return 0;
	}
	if(OpenClipboard(NULL)) //OpenClipboard()是打开剪切板成功返回TRUE 失败返回FALSE
	{
		HANDLE handle;
		char* pBuf;
		EmptyClipboard(); //清空剪切板获得剪切板权限
		handle=GlobalAlloc(GMEM_MOVEABLE,nlen + 1); //申请内存空间                                                  
		pBuf=(char*)GlobalLock(handle); //加锁空间
		memcpy(pBuf,lpBuf, nlen); //给空间写入数据
		GlobalUnlock(handle); //解锁空间
		SetClipboardData(CF_TEXT,handle);  //设置剪切板中数据
	}
	CloseClipboard();  //关闭剪切板 一定要关闭 否则其他程序无法使用剪切板
	return 0;
}

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

// 插件可以从plugins.cfg文件中，被传进一个整型参数。
// 当按下不同的热键或者菜单时，您需要一个插件做不同
// 的事情时，这非常有用。
void __stdcall IDAP_run(int arg)
{
	char szBuf[512] = {0};
#ifdef __EA64__
	sprintf(szBuf, "0x%llX", get_screen_ea());
#else
	sprintf(szBuf, "0x%08X", get_screen_ea());
#endif 
	SnedClipData(szBuf, strlen(szBuf));
	msg("SendScreenAddrClip: %s\n", szBuf);
	return;
}
// 下面的这些字符都是可以自行设定的
char IDAP_comment[] = "Comment of my first ida plugin. By: 空道.";
char IDAP_help[] = "http://bbs.chinapyg.com/";
// 在Edit->Plugins 菜单中，插件的现实名称，
// 它能被用户的plugins.cfg文件改写
char IDAP_name[] = "KDSendScreenAddrClip";
// 启动插件的热键，纯字符的定义，比较易懂
char IDAP_hotkey[] = "Shift-Alt-x";
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