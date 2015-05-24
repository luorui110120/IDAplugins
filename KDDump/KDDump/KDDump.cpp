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

char *dialog =			//给窗口布局
"STARTITEM 0\n"			//让第一项获得焦点
"Dump Data \n\n"	//窗口标题
"Please Input Addr\n"	//文本内容
#ifdef __EA64__
"<#数据地址 0x#StartAddr  :M:17:16::>\n"	//一个16进制数
"<#数据地址 0x#EndAddr/Len:M:17:16::>\n"	//一个16进制数
#else
"<#数据地址 0x#StartAddr  :M:9:16::>\n"	//一个16进制数
"<#数据地址 0x#EndAddr/Len:M:9:16::>\n"	//一个16进制数
#endif
"<##Option##EndAddr:R>\n"	//给单选框提供组
"<Len:R>>\n"		//组内的第二个
"<##Check Boxes##StartAddr设为段首地址:C>>\n";

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
	// 插件的实体
	//在LOG中显示一个字符串
	char *lpSavePath;
	char szFileName[256] = {0};
	//	char szTmp[100] = {0};
	segment_t *curseg;
	USHORT nRadio = 0;
	USHORT checkmask = 0;
	ea_t nStartAddres = get_screen_ea();
	ea_t nEndAddres = nStartAddres + 0x100;
	int j = 0;
	int i = 0;
	FILE *handle;
	FILE *f;
	asize_t size = 0;
	int nCover = 0;
	//	qstrncpy(szInValue,"",sizeof(szInValue));
	if( curseg = getseg(nStartAddres))
	{
		nEndAddres = curseg->endEA;;
	}
	while(!isLoaded(nEndAddres - 1))
	{
		nEndAddres -= 0x100;
	}
	if(AskUsingForm_c(dialog, &nStartAddres, &nEndAddres, &nRadio, &checkmask) == 1)
	{
		if(checkmask)
		{
			nStartAddres = curseg->startEA;
		}
		if(nRadio)
		{
			nEndAddres += nStartAddres;
		}
		msg("==============开始Dump数据==============\n");
#ifdef __EA64__
		msg("StartAddres:0x%llX  EndAddres:0x%llX\n", nStartAddres, nEndAddres);
#else
		msg("StartAddres:0x%08X  EndAddres:0x%08X\n", nStartAddres, nEndAddres);
#endif
		if(isLoaded(nStartAddres) && isLoaded(nEndAddres - 1))
		{
			size = nEndAddres - nStartAddres;
			if(size > 0)
			{
#ifdef __EA64__
				sprintf(szFileName, "%llX-%llX.Dump", nStartAddres, nEndAddres);
#else
				sprintf(szFileName, "%08X-%08X.Dump", nStartAddres, nEndAddres);
#endif
				lpSavePath = askfile_cv(1, szFileName, "SavePath", 0);
				if(lpSavePath == NULL)
				{
					msg("取消了Dump\n");
					return;
				}
				if( (f = fopen(lpSavePath, "r")) != NULL)
				{
					fclose(f);
					if( askyn_c(1, "是否覆盖文件") <= 0)
					{
						warning("Dump 失败!\n");
						return;
					}
				}
				handle = fopenWB(lpSavePath);
				if(handle == NULL)
				{
					warning("打开文件失败 Error!\n");
					return;
				}
				
				uchar * mem = (uchar *)qalloc(size + 1);
				get_many_bytes(nStartAddres,mem, size);
				ewrite(handle, mem, size);
				eclose(handle);
				qfree(mem);
				msg("SavePath:%s\n", lpSavePath);
				msg("==============Dump数据成功==============\n");
			}
			else
			{
				warning("Error !Size 小于零!\n");
			}
		}
		else
		{
			if(!isLoaded(nStartAddres))
			{
				warning("Error!  StartAddres地址不存在!\n");
			}
			else
			{
				warning("Error!  EndAddres地址不存在!\n");
			}

		}

	}
	return;
}
// 下面的这些字符都是可以自行设定的
char IDAP_comment[] = "Comment of my first ida plugin. By: 空道.";
char IDAP_help[] = "http://bbs.chinapyg.com/";
// 在Edit->Plugins 菜单中，插件的现实名称，
// 它能被用户的plugins.cfg文件改写
char IDAP_name[] = "KDDump";
// 启动插件的热键，纯字符的定义，比较易懂
char IDAP_hotkey[] = "Alt-d";
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