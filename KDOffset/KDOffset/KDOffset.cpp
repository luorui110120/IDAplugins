#include <windows.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>



#pragma comment(lib,"ida.lib")
#define  MSG msg
#define  USHORT ushort



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
// 插件可以从plugins.cfg文件中，被传进一个整型参数。
// 当按下不同的热键或者菜单时，您需要一个插件做不同
// 的事情时，这非常有用。
void __stdcall IDAP_run(int arg)
{
	ea_t nOffsetAddr = get_fileregion_offset(get_screen_ea());
	static char *dialog =			//给窗口布局
		"STARTITEM 0\n"			//让第一项获得焦点
		"JUMP Offset \n\n"
#ifdef __EA64__
		"<#数据地址 0x#Offset  :M:17:16::>\n";
#else
		"<#数据地址 0x#Offset  :M:9:16::>\n";
#endif
	if(AskUsingForm_c(dialog, &nOffsetAddr) == 1)
	{
		jumpto(get_fileregion_ea(nOffsetAddr));
	}
	return;
}
// 下面的这些字符都是可以自行设定的
char IDAP_comment[] = "Comment of my first ida plugin. By 空道";
char IDAP_help[] = "www.chinapy.com";
// 在Edit->Plugins 菜单中，插件的现实名称，
// 它能被用户的plugins.cfg文件改写
char IDAP_name[] = "KDOffset";
// 启动插件的热键，纯字符的定义，比较易懂
char IDAP_hotkey[] = "Shift-Alt-G";
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