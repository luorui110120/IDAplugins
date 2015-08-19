#include <windows.h>
#include <Shlwapi.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>
#include "ChineseCode.h"


#pragma comment(lib,"ida.lib")
#pragma comment(lib, "Shlwapi.lib")
#define  MSG msg
#define  USHORT ushort
#define  byte uchar
#define  UINT32 uint

static HINSTANCE g_hinstPlugin = NULL;
static char g_szIniPath[MAX_PATH] = { 0 };
static char g_szCopuStringSection[] = "KDCopyString";
static char g_szOptionsKey[] = "Options";
static int g_CheckClip = 1;
static int g_Index = 0;
static const char g_CodeTable[][256] = {"UTF-8", "GB2132", "Unicode"}; 
///////////////////////////////////////////////个人修改增强版支持模糊匹配
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
///////////////////////////////
char *dialog =			//给窗口布局
"STARTITEM 0\n"			//让第一项获得焦点
"选中对应的编码\n\n"	//窗口标题
#ifdef __EA64__
"<#数据地址 0x#Addres:M:17:16::>\n"
#else
"<#数据地址 0x#Addres:M:9:16::>\n"
#endif
"<##Options##UTF-8:R>\n"	//给单选框提供组
"<GB2132:R>\n"		//组内的第二个
"<Unicode:R>>\n"
"<##Check Boxes##是否将结果发送到剪切板:C>>\n";

//编写配置文件
int WritePluginCfg(char *lpFilePath, char *lpPluginName)
{
	char szBuf[256] = {0};
	sprintf(szBuf, "\tCopyStringOptions\t%s\t\"\"\t1", lpPluginName);
	FILE *lpf = fopen(lpFilePath, "rb");
	fseek(lpf, 0, SEEK_END);
	int nFileSize = ftell(lpf);
	fseek(lpf, 0, SEEK_SET);
	char *lpFileBuf = (char*)malloc(nFileSize + 1);
	memset(lpFileBuf, 0, nFileSize + 1);
	fread(lpFileBuf, 1, nFileSize, lpf);
	fclose(lpf);
	//	warning("%s\n", lpFileBuf);
	if(strstr(lpFileBuf, szBuf) == NULL)
	{
		lpf = fopen(lpFilePath, "a+");
		fwrite("\n", 1, 1, lpf);
		fwrite(szBuf, 1, strlen(szBuf), lpf);
		fclose(lpf);
	}
	free(lpFileBuf);
	return 0;
}
int __stdcall IDAP_init(void)
{
	//在这里做一些校验，以确保您的插件是被用在合适的环境里。
	//返回PLUGIN_SKIP 、PLUGIN_OK或者PLUGIN_KEEP，具体含义见后文
	GetModuleFileName(g_hinstPlugin, g_szIniPath, sizeof(g_szIniPath));
	g_szIniPath[sizeof(g_szIniPath) - 1] = '\0';

	/* Change the extension of plugin to '.ini'. */
	PathRenameExtension(g_szIniPath, ".ini");
	if(INVALID_FILE_ATTRIBUTES == GetFileAttributes(g_szIniPath))
	{
		char szPluginCfgPath[256] = {0};
		char szModuleName[256] = {0};

		strcpy( szPluginCfgPath, g_szIniPath);
		strcpy(szModuleName, strrchr(szPluginCfgPath, '\\') + 1);
//		*strrchr(szPluginCfgPath, '\\') = 0;
		*strrchr(szModuleName, '.') = 0;
//		strcat(szPluginCfgPath, "\\plugins.cfg");
//		WritePluginCfg(szPluginCfgPath, szModuleName);
		//	warning("cfgPath:%s\n ModuleName:%s\n", szPluginCfgPath, szModuleName);
	}
	/* Get options saved in ini file */
	g_Index = GetPrivateProfileInt(g_szCopuStringSection, g_szOptionsKey, 0, g_szIniPath);
	g_CheckClip = GetPrivateProfileInt(g_szCopuStringSection, "CheckClip", 1, g_szIniPath);

	return PLUGIN_KEEP;

}
void WriteIniFile()
{
	char szBuf[] = "可使用 ACSII, UTF-8, UNICODE 三种编码对应索引为0,1,2     可通过按住shift 然后点击Edit->Plugins->CopyStringOptions去配置ini文件";
	char szIndex[10] = {0};
	itoa(g_Index, szIndex, 10);
	WritePrivateProfileString(g_szCopuStringSection, g_szOptionsKey, szIndex, g_szIniPath);
	itoa(g_CheckClip, szIndex, 10);
	WritePrivateProfileString(g_szCopuStringSection, "CheckClip", szIndex, g_szIniPath);
	WritePrivateProfileString(g_szCopuStringSection, "说明", szBuf, g_szIniPath);
}
void __stdcall IDAP_term(void)
{
	//当结束插件时，一般您可以在此添加一点任务清理的代码。
	WriteIniFile();
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
int ReadString(uval_t nAddres, char *lpOutBuf)
{
	int i = 0;
	int iRet = 0;
	switch (g_Index)
	{
	case 0:
		{
			char chTmp = 0;
			char *lpTmpBuf = (char *)malloc(0x1000 * sizeof(char));
			memset(lpTmpBuf, 0, 0x1000 * sizeof(char) );
			while( (chTmp = get_byte(nAddres + i)) && (i < 0x1000))
			{
				lpTmpBuf[i++] = chTmp;
			}
			iRet = Utf8ToGB2312(lpTmpBuf, strlen(lpTmpBuf), lpOutBuf);
			free(lpTmpBuf);
		}
		break;
	case 1:
		{
			char chTmp = 0;
			while( (chTmp = get_byte(nAddres + i)) && (i < 0x1000))
			{
				lpOutBuf[i++] = chTmp;
			}
			iRet = i;
		}
		break;
	case 2:
		{
			ushort usTmp = 0;
			ushort *lpTmpBuf = (ushort *)malloc(0x1000 * sizeof(ushort));
			memset(lpTmpBuf, 0, 0x1000 * sizeof(ushort) );
			while( (usTmp = get_word(nAddres + i * 2)) && (i < 0x1000))
			{
				lpTmpBuf[i++] = usTmp;
			}
			iRet = UnicodeToGB2132((wchar_t *)lpTmpBuf, wcslen((wchar_t*)lpTmpBuf), lpOutBuf);
			free(lpTmpBuf);
		}
		break;
	default:
		break;
	}
	return iRet;
}
void __stdcall IDAP_run(int arg)
{
	//msg("IDAP_run arg: %d \ng_Index:%d \ng_Path :%s\n", arg, g_Index, g_szIniPath);
	// 插件的实体
	//在LOG中显示一个字符串
	msg("============开始复制字符串==============\n");
	uval_t nAddres = get_screen_ea();
	int i = 0;
	int j = 0;
	UINT32 size = 0;
	int nCover = 0;
	USHORT checkmask = 0;
	char *lpBuf = (char *)malloc(0x1000);
	memset(lpBuf, 0, 0x1000);
	if (GetAsyncKeyState(VK_SHIFT) & 0x8000)
	{
		if(AskUsingForm_c(dialog, &nAddres, &g_Index, &g_CheckClip) == 1)
		{
			WriteIniFile();
			if(!isLoaded(nAddres))
			{
				msg("地址无效!读取数据失败!\n");
				return;
			}
			else
			{
				size = ReadString(nAddres, lpBuf);
			}
		}
	}
	else
	{
		size = ReadString(get_screen_ea(), lpBuf);
	}
	if(g_CheckClip && size)
	{
		msg("已将结果发送至送剪切板!\n");
		SnedClipData(lpBuf, size);
	}
	msg("使用%s编码打印字符串:\n%s\n", g_CodeTable[g_Index], lpBuf);
	free(lpBuf);
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
char IDAP_comment[] = "Comment of my first ida plugin MyFind. By 空道";
char IDAP_help[] = "http://bbs.chinapyg.com/";
// 在Edit->Plugins 菜单中，插件的现实名称，
// 它能被用户的plugins.cfg文件改写
char IDAP_name[] = "KDCopyString";
// 启动插件的热键，纯字符的定义，比较易懂
char IDAP_hotkey[] = "Alt-i";
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