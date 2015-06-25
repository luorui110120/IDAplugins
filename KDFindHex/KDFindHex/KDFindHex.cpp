#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>
#include <dbg.hpp>


#pragma comment(lib,"ida.lib")
#define  MSG msg
#define  USHORT ushort
#define  byte uchar
#define  UINT32 uint

///////////////////////////////////////////////个人修改增强版支持模糊匹配
///////////支持 模糊匹配
void getnext_bin(int sub[], int subSize, int next[])
{
	// 得到next数据,其实本质是自身KMP匹配
	//	printf("sub bin array : ");
	int i,j;
	i = 0;
	j = -1;
	next[0] = -1;
	//printf("%d", next[i]);
	while(i+1 < subSize)
	{
		if(j==-1 || sub[i]==sub[j] || sub[j] == -1)
		{
			++i;
			++j;
#if 1
			if (sub[i] != sub[j])
			{
				next[i] = j;
			}
			else
			{
				next[i] = next[j];
			}

#else
			next[i] = j;
#endif
			//printf(", %d",next[i]);
		}
		else 
		{
			j = next[j];
		}
	}
	//printf("\n");
}

bool kmpcmp(unsigned char by, int sub)
{
	if( (by & (~(sub >> 24))) == (sub & 0xFF) )
	{
		return true;
	}
	return false;
}
int kmp_bin(unsigned char main[], int mainSize, int sub[], int subSize, int next[])
{
	// 返回s在m中的第一个数据的下标
	int i,j;
	i = 0;
	j = 0;
	int nIndex = -1;
	while(i < mainSize)
	{
		if(j==-1 || sub[j] == -1 || kmpcmp(main[i], sub[j]))
		{
			++i;
			++j;
			if(j == subSize)
			{
				nIndex = (i-j);
				break;
			}
		}
		else
		{
			j = next[j];
		}
	}
	return nIndex;
}
int CharToHex(char ch)
{
	const char szTable[16] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46};
	int i = 0;
	for(i = 0; i < sizeof(szTable); i++)
	{
		if(ch == szTable[i])
		{
			return i;
		}
	}
	return -1;
}
/////////////////////////////////////
// 函数名称:kmp
// 函数功能:二进制kmp 搜索算法
// 函数参数:matcher:被搜索的地址
// 函数参数:mlen:搜索空间
// 函数参数:pattern: 查找的16进制字符串
// 函数参数:plen:关键字长度
// 函数参数:nStartPost: 缓冲区的起始位置
// 函数返回值:成功返回索引,否则-1
//////////////////////////////////////////
int kmp( unsigned char *matcher, unsigned int mlen, char *pattern, unsigned int plen, int nStartPost)
{

	
	int iRet = 0;
	int nLen = plen / 2;
	int *lpNext = (int *) malloc( (nLen + 1) * sizeof(int));
	int *lpSub = (int *) malloc( (nLen + 1) * sizeof(int));
	int i = 0;
	memset(lpNext, 0, (nLen + 1) * sizeof(int));
	memset(lpSub, 0, (nLen + 1) * sizeof(int));
	for(i = 0; i < nLen; i ++)
	{
		if(pattern[i * 2] == '?' && pattern[i * 2 + 1] == '?')
		{
			lpSub[i] = -1;
		}
		else if(pattern[i * 2] == '?')
		{
			lpSub[i] = 0xF0000000 + CharToHex(pattern[i * 2 + 1]);
		}
		else if(pattern[i * 2 + 1] == '?')
		{
			lpSub[i] = 0x0F000000 + CharToHex(pattern[i * 2]) * 0x10;
		}
		else
		{
			sscanf(pattern + i * 2, "%02X", lpSub + i);
		}
	}
	getnext_bin(lpSub, nLen, lpNext);
	iRet = kmp_bin(matcher + nStartPost, mlen - nStartPost, lpSub, nLen, lpNext);
	free(lpNext);
	free(lpSub);
	if(iRet < 0)
	{
		return iRet;
	}
	else
	{
		return iRet + nStartPost;
	}
}
//通过uAddr地址查找到所属的区段
int FindSegIndex(uval_t uAddr)
{
	int seg_qty = get_segm_qty();
	int i = 0;
	segment_t *curseg;
	for(i = 0; i < seg_qty; i++)
	{
		curseg = getnseg(i);
		if(uAddr >= curseg->startEA && uAddr< curseg->endEA)
		{
			return i;
		}
	}
	return -1;
}
///////////////////////////////
char *dialog =			//给窗口布局
	"STARTITEM 0\n"			//让第一项获得焦点
	"特征码搜索模糊匹配使用?代替\n\n"	//窗口标题
	"Please enter the hexadecimal data size less 0x200\n"	//文本内容
	"<Hex						:A:1024:32::>\n"	//  256表示结束字符串输入的长度,  32表示 输入框的 宽度第一项字符串数据
#ifdef __EA64__
	"<#数据地址 0x#StartAddr:M:17:16::>\n"	//一个16进制数
	"<#数据地址 0x#EndAddr		:M:17:16::>\n"	//一个16进制数
#else
	"<#数据地址 0x#StartAddr:M:9:16::>\n"	//一个16进制数
	"<#数据地址 0x#EndAddr		:M:9:16::>\n"	//一个16进制数
#endif
	"<#列出所有匹配地址:C>>\n"
	"<#跳转到第一个结果:C>>\n"
	"<#StartAddr设为段首地址:C>>\n"
	"<#搜索所有段:C>>\n";



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
	char szValue[MAXSTR + 1] = "";
	char szInValue[MAXSTR + 1] = "";
	//	char szTmp[100] = {0};
	ea_t nStartAddres = get_screen_ea();
	ea_t nEndAddres = nStartAddres + 0x100;
	int FindAddr = 0;
	int i = 0;
	int j = 0;
	UINT32 size = 0;
	int nCover = 0;
	segment_t *curseg;
	USHORT checkmask = 1;
	USHORT checkjumpto = 1;
	USHORT checkStrartEA = 1;
	USHORT checkAllSeg = 0;
	//	qstrncpy(szInValue,"",sizeof(szInValue));
	////下面两部操作 可直接调用getseg函数代替
	i = FindSegIndex(nStartAddres);
	if(i >= 0)
	{
		segment_t *curseg = getnseg(i);
		nEndAddres = curseg->endEA;
	}
	while(!isLoaded(nEndAddres - 1))
	{
		nEndAddres -= 0x100;
	}
	if(PLFM_ARM == ph.id)
	{
		regval_t  val;
		get_reg_val("pc", &val);
		if(val.ival == -1)
		{
			checkAllSeg = 1;
			checkStrartEA = 0;
		}
	}
	else
	{
		regval_t  val;
		get_reg_val("eip", &val);
		if(val.ival == -1)
		{
			checkAllSeg = 1;
			checkStrartEA = 0;
		}
	}
	if(AskUsingForm_c(dialog, szInValue, &nStartAddres, &nEndAddres, &checkmask, &checkjumpto, &checkStrartEA, &checkAllSeg) == 1)
	{
		if(checkAllSeg & 1)
		{
			int seg_qty = get_segm_qty();
			if(seg_qty > 0)
			{
				curseg = getnseg(0);
				nStartAddres = curseg->startEA;
				nEndAddres = curseg->endEA - 1;
				for(i = 1; i < seg_qty; i++)
				{
					curseg = getnseg(i);
					if(isLoaded(curseg->endEA - 1) )// && SEG_CODE == curseg->type)
					{
						nEndAddres = curseg->endEA - 1;
					}
				}

			}
		}
		else if(checkmask & 1)
		{
			//	nAddres = get_screen_ea();
			
			if( curseg = getseg(nStartAddres))
			{
				nStartAddres = curseg->startEA;;
			}
		}

		int len = strlen(szInValue);
		for(i = 0; i < len; i++)
		{
			if(szInValue[i] != ' ')
			{
				szValue[j++] = szInValue[i];
			}
		}
		len = strlen(szValue);
		int nHexLen = len / 2;
		if(!len)
		{
			warning("请输入数据");
			return;
		}
		if(len % 2)
		{
			warning("过滤空格后数据长度不是2的倍数");
			return;
		}
		for(i = 0;i < len;i++)
		{
			if(szValue[i] != '?'&& !isxdigit(szValue[i]))
			{
				warning("数据中含非法字符");
				return;
			}
		}
		msg("==============开始搜索==============\n");
#ifdef __EA64__
		msg("StartAddres:0x%llX  EndAddres:0x%llX\n", nStartAddres, nEndAddres);
#else
		msg("StartAddres:0x%08X  EndAddres:0x%08X\n", nStartAddres, nEndAddres);
#endif
		msg("搜索特征码为:%s\n结果如下:\n", szValue);
		if(isLoaded(nStartAddres) && isLoaded(nEndAddres - 1))
		{
			size = nEndAddres - nStartAddres;
			if(size > 0)
			{
				uchar *mem = (uchar *)malloc(size + 1);
				get_many_bytes(nStartAddres,mem, size);
				do
				{
					FindAddr = kmp(mem, size, szValue, len, FindAddr);
					if(FindAddr < 0)
					{
						break;
					}
					else
					{
					#ifdef __EA64__
						msg("0x%llX\n", FindAddr + nStartAddres);
					#else
						msg("0x%08X\n", FindAddr + nStartAddres);
					#endif
						if(checkjumpto)
						{
							checkjumpto = 0;
							ea_t addr = FindAddr + nStartAddres;
							if(!jumpto(addr))
							{
								msg("jumpto Error!");
							}
						}
					}
					FindAddr += nHexLen;
				}while(checkmask == 1);
				free(mem);
				msg("==============搜索结束==============\n");
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
char IDAP_comment[] = "Comment of my first ida plugin MyFind. By 空道";
char IDAP_help[] = "http://bbs.chinapyg.com/";
// 在Edit->Plugins 菜单中，插件的现实名称，
// 它能被用户的plugins.cfg文件改写
char IDAP_name[] = "KDFindHex";
// 启动插件的热键，纯字符的定义，比较易懂
char IDAP_hotkey[] = "shift-Alt-f";
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