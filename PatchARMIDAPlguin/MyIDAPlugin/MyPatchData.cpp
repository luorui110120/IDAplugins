#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <stdio.h>


#pragma comment(lib,"ida.lib")
#define  MSG msg
#define  USHORT ushort

char *dialog =			//给窗口布局
	"STARTITEM 0\n"			//让第一项获得焦点
	"Patch Datan\n\n"	//窗口标题
	"Please enter the hexadecimal data size less 0x200\n"	//文本内容
	"<String:A:32:32::>\n"	//第一项字符串数据
	"<#数据地址 0x#Addres:M:9:16::>\n"	//一个16进制数
	"<循环次数  0x#nCount:M:9:16::>\n"	//一个16进制数据
	// "<循环次数:D:256:10::>\n"	//一个10进制数据	//注意这里的256 就是输入数字的范围  后面的15表示编辑宽的长度
	"<##覆盖写入或者异或写入##Write:R>\n"	//给单选框提供组
	"<XorWrite:R>>\n"		//组内的第二个
	"<##Check Boxes##取光标地址 忽略Addres值:C>>\n";	//给复选框提供组


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
	char *lpInBuf = NULL;
	char *lpTmpBuf = NULL;
	char *lpFilePath = NULL;
	char szValue[MAXSTR + 1] = "";
	char szInValue[MAXSTR + 1] = "";
	//	char szTmp[100] = {0};
	int nPatchLogFlags = 1;
	uval_t nAddres = get_screen_ea();
	asize_t nCount = 1;
	USHORT nRadio = 0;		//单选按钮
	USHORT checkmask = 0;
	uint32 j = 0;
	uint32 i = 0;
	//	qstrncpy(szInValue,"",sizeof(szInValue));

	if(AskUsingForm_c(dialog, szInValue, &nAddres, &nCount, &nRadio, &checkmask) == 1)
	{
		if(checkmask & 1)
		{
			nAddres = get_screen_ea();
		}
		uint32 len = strlen(szInValue);
		for(i = 0; i < len; i++)
		{
			if(szInValue[i] != ' ')
			{
				szValue[j++] = szInValue[i];
			}
		}
		len = strlen(szValue);
		uint32 nHexLen = len / 2;
		if(!len)
		{
			if( lpFilePath = askfile_cv(0, "*.*", "OpenPath", 0))
			{
				FILE* handle = fopen(lpFilePath, "rb");
				if(handle == NULL)
				{
					warning("打开文件失败 Error!\n");
					return;
				}
				fseek(handle, 0, SEEK_END);
				nHexLen = ftell(handle);
				fseek(handle, 0, SEEK_SET);
				lpTmpBuf = (char *)malloc(nHexLen + 1);
				memset(lpTmpBuf, 0, nHexLen + 1);
				fread(lpTmpBuf, 1, nHexLen, handle);
				fclose(handle);
				strcpy(szValue, lpFilePath);
			}
			else
			{
				warning("请输入数据");
				return;
			}

		}
		else if(len % 2)
		{
			warning("数据长度不是2的倍数");
			return;
		}
		else
		{
			for(i = 0;i < len;i++)
			{
				if(!isxdigit(szValue[i]))
				{
					warning("数据中含有非16进制值");
					return;
				}
			}
			lpTmpBuf = (char *) malloc(nHexLen + 1);
			memset(lpTmpBuf, 0, nHexLen + 1);
			for(i = 0; i < nHexLen; i++)
			{
				sscanf(&szValue[i * 2],"%02x",lpTmpBuf + i);
			}
		}
		lpInBuf = (char*)malloc(nHexLen * nCount + 1);
		memset(lpInBuf, 0, nHexLen * nCount + 1);
		for(i = 0; i < nCount; i++)
		{
			memcpy(lpInBuf + i * nHexLen, lpTmpBuf, nHexLen);
		}
		free(lpTmpBuf);

		msg("==============修补数据库数据==============\n");
		msg("String Value = %s\n",szValue);
		msg("Addres:0x%08X  ValueSize = 0x%08X  Index:%d check = %d\n",nAddres, nHexLen, nCount,checkmask);
		if(!nRadio)
		{
			MSG("WriteData \n",nRadio);
		}
		else
		{
			MSG("XorWrite Data \n",nRadio);
		}
		if( nHexLen * nCount > 0x100)
		{
			nPatchLogFlags = askyn_c(0, "%s", "是否打印日志!(默认不打印)\n因为数据量过大会影响IDA会假死!\nNo或Cancel表示不打印日志!\n");
		}
		////////////////////	
		uint32 nSum = 0;
		uchar *mem = NULL;
		if(isLoaded(nAddres) && isLoaded(nAddres + nCount *  nHexLen - 1))
		{

			mem = (uchar *)malloc(nCount *  nHexLen + 1);
			if(mem == NULL)
			{
				warning("malloc 函数执行失败!");
				return;
			}
			get_many_bytes(nAddres,mem, nCount *  nHexLen);
			if(nPatchLogFlags > 0)
			{
				msg("原始数据:\n");
				for(i = 0; i < nCount *  nHexLen; i++)
				{	
					msg("%02X", mem[i]);
				}
				msg("\n");
			}

		}
		else
		{
			if(!isLoaded(nAddres))
			{
				warning("数据地址错误: 0x%p",nAddres);
			}
			else
			{
				warning("写入数据长度过大");
			}
			return;
		}
		///////////////////////////
		//		long nValue = 0;
		for(j = 0;j < nCount;j++)
		{
			for(i = 0;i < nHexLen; i++)
			{
				//				memcpy(szTmp,&szInValue[j * len + i * 2],2);
				//sscanf(&szValue[i * 2],"%02x",&nValue);
				if(nRadio == 1)
				{
					lpInBuf[nSum] ^=   mem[nSum];
				}
				mem[nSum++] = lpInBuf[nSum];

			}
		}
		put_many_bytes(nAddres, mem, nSum);
		if(nPatchLogFlags > 0)
		{
			msg("补丁数据:\n");
			for(i = 0; i < nSum; i++)
			{	
				msg("%02X", mem[i]);
			}
			msg("\n");
		}
		refresh_idaview_anyway();		//刷新反汇编窗口
		free(mem);
		free(lpInBuf);

	}
	return;
}
// 下面的这些字符都是可以自行设定的
char IDAP_comment[] = "Comment of my first ida plugin. By 空道";
char IDAP_help[] = "www.chinapy.com";
// 在Edit->Plugins 菜单中，插件的现实名称，
// 它能被用户的plugins.cfg文件改写
char IDAP_name[] = "Patch Addres Data";
// 启动插件的热键，纯字符的定义，比较易懂
char IDAP_hotkey[] = "Alt-P";
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