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

using namespace std;

#pragma comment(lib,"ida.lib")
#pragma comment(lib, "Shlwapi.lib")
#define  MSG msg
#define  USHORT ushort
char headers[][256] = {"Addr", "Comment"};
int widths[] = {16,48};

vector<string> ldFilterData;
//vector<string> ldTmpData;
int nCommentCount;
static char g_szDefalutFilters[][256] = 
{
	"status", "ptr", "fd", "size", "src", "dest", "s2", "domain", "type", "protocol", "addr", "len",
	"name", "in", "addr_len", "unsigned int", "nptr", "buf", "void *", "stream", "s1", "haystack",
	"needle", "path", "pid", "sig", "sysno", "int", "request", "errnum", "options", "stat_loc",
	"signo", "threadid", "writefds", "exceptfds", "readfds", "nfds", "timeout", "flags", "timer",
	"env", "val", "off", "whence", "modes", "accept", "resolved", "mode", "offset", "operation",
	"oflag", "file", "tp", "maxsize", "format", "tz", "tv", "clock_id", "nbytes", "attr",
	"mutexattr", "mutex", "abstime", "sem", "thread_return", "value", "replace", "thread2", 
	"detachstate", "arg", "start_routine", "newthread", "mask", "pshared", "fd2", "string", 
	"pgid", "argv", "pattern", "cmp", "namelist", "selector", "dir", "length", "maxlen", "dirp", "cmd",
	"size_t", "level", "lParam", "lcid", "item", "float", "char", "char *", "__int64", 
};
static char g_szIniPath[MAX_PATH] = { 0 };
static HINSTANCE g_hinstPlugin = NULL;

typedef struct _ListData
{
	ea_t eaAddr;
	string strValue;
}ListData;
vector<ListData> ldData;
vector<ListData> ldCommentData;
class AUTO_BUFFER
{
private:
	int m_used_size;
	int m_buff_size;
	int m_alloc_granularity;

public:
	AUTO_BUFFER(int init_size, int alloc_granularity = 0)
	{
		if(alloc_granularity == 0)
			m_alloc_granularity = init_size;
		else
			m_alloc_granularity = alloc_granularity;

		m_used_size = 0;
		m_buff_size = init_size;
		m_ptr = new char[init_size]; 
	}

	~AUTO_BUFFER()
	{
		delete m_ptr;
	}

	void Put(char * in_buff, int in_buff_size)
	{
		if(m_used_size + in_buff_size > m_buff_size)
		{
			while(m_buff_size < m_used_size + in_buff_size)
				m_buff_size += m_alloc_granularity;

			char * temp_new = new char[m_buff_size];
			char * temp_old = m_ptr;

			memcpy(temp_new, temp_old, m_used_size);

			delete temp_old;
			m_ptr = temp_new;
		}

		memcpy(m_ptr+m_used_size, in_buff, in_buff_size);		
		m_used_size += in_buff_size;
	}

	int Size()
	{
		return m_used_size;
	}

	char* Get()
	{
		return m_ptr;
	}

	char *m_ptr;
};


static const char form[] =
"STARTITEM 0\n"
"Filter choosers\n\n"
"<Temporary filter:E3::30::>\n\n";
//"<Permanent filter:E3::30::>>\n\n";

int WriteFilterIni(char *lpFilePath, vector<string> &ldFilter)
{
	int i = 0;
	FILE *f = fopen(lpFilePath, "w+");
	int nCount = ldFilter.size();
	for(i = 0; i < nCount; i++)
	{
		fwrite(ldFilter.at(i).c_str(), 1, ldFilter.at(i).length(), f);
		fwrite("\n", 1, 1, f);
	}
	fclose(f);
	return 0;
}
int __stdcall IDAP_init(void)
{
	//在这里做一些校验，以确保您的插件是被用在合适的环境里。
	//返回PLUGIN_SKIP(不加载) 、PLUGIN_OK或者PLUGIN_KEEP，具体含义见后文
	int i = 0;
	msg("Comment List pulgin init\n");
	GetModuleFileName(g_hinstPlugin, g_szIniPath, sizeof(g_szIniPath));
	g_szIniPath[sizeof(g_szIniPath) - 1] = '\0';

	/* Change the extension of plugin to '.ini'. */
	PathRenameExtension(g_szIniPath, ".ini");
	if(INVALID_FILE_ATTRIBUTES == GetFileAttributes(g_szIniPath))
	{
		int nCount = sizeof(g_szDefalutFilters) / sizeof(g_szDefalutFilters[0]);
		for(i = 0; i < nCount; i++)
		{
			ldFilterData.push_back(string(g_szDefalutFilters[i]));
		}
		WriteFilterIni(g_szIniPath, ldFilterData);
	}
	else
	{
		FILE *f = fopen(g_szIniPath, "r");
		char szTmpBuf[256] = {0};
		while(!feof(f))
		{
			memset(szTmpBuf, 0, 256);
			fgets(szTmpBuf, 256, f);
			if(strlen(szTmpBuf) > 1)
			{
				szTmpBuf[strlen(szTmpBuf) - 1] = 0;
				ldFilterData.push_back(string(szTmpBuf));
			}
			
		}
		fclose(f);
	}
	
	return PLUGIN_OK;
}
void __stdcall IDAP_term(void)
{
	//当结束插件时，一般您可以在此添加一点任务清理的代码。
	return;
}
int VectorFind(string strValue, vector<string> &ldFindData)
{
	int nCount = ldFindData.size();
	int i = 0;
	for(i = 0; i < nCount; i++)
	{
		if( strValue == ldFindData[i])
		{
			break;
		}
	}
	if(i < nCount)
	{
		return i;
	}
	return -1;
}
void idaapi idaListComment_enter(void * obj,uint32 n)
{
	segment_t *curseg;
	curseg = getnseg(0);
	ea_t addr = 0;
	vector<ListData> *lpvldData = (vector<ListData>*) obj;
	if(curseg)
	{
		addr = curseg->startEA + lpvldData->at(n - 1).eaAddr;
	}
	else
	{
		addr = lpvldData->at(n - 1).eaAddr;
	}
	jumpto(addr);
#ifdef __EA64__
	msg("enter:0x%llX\n", addr);
#else
	msg("enter:0x%08X\n", addr);
#endif
	
}


ulong idaapi idaListComment_sizer(void *obj)
{
	vector<ListData> *lpvldData = (vector<ListData>*) obj;
	return lpvldData->size();
}
void idaapi idaListComment_getlien2(void *obj, ulong n, char* const *cells)
{
// 	if(nflasg && n == 0)
// 	{
// 		msg("jin %d\n", n);
// 		nflasg = 0;
// 	}
	
//	msg("getLient: %d\n %08X\n", n, (uint32)obj);
	segment_t *curseg;
	curseg = getnseg(0);
	ea_t addr = 0;
	vector<ListData> *lpvldData = (vector<ListData> *)obj;
	int i = 0;
	int nCells = sizeof(headers) / sizeof(headers[0]);
	if(n > lpvldData->size())
	{
		return;
	}
	if(n == 0)
	{
		for(i = 0; i < nCells; i++)
		{
			qstrncpy( cells[i], headers[i], qstrlen(headers[i]) + 1);
		}
	}
	else
	{
		if(curseg)
		{
			addr = curseg->startEA + lpvldData->at(n -1).eaAddr;
		}
		else
		{
			addr = lpvldData->at(n -1).eaAddr;
		}
#ifdef __EA64__
		qsnprintf(cells[0], 0x100, "0x%llX", addr);
#else
		qsnprintf(cells[0], 0x100, "0x%08X", addr);
#endif
		qstrncpy(cells[1], lpvldData->at(n -1).strValue.c_str(), 1024);
		
	}
}

uint32 idaapi idaListFilter_delete(void *obj, uint32 n)
{
	vector<string> *lpvStr = (vector<string> *)obj;
	vector<string>::iterator it = lpvStr->begin() + n - 1;
	lpvStr->erase(it);
	return lpvStr->size();
}
void idaapi idaListFilter_enter(void * obj,uint32 n)
{
	vector<string> *lplds = (vector<string> *)obj;
	msg("ListFilter: %s\n", lplds->at(n - 1).c_str());
}
ulong idaapi idaListFilter_sizer(void *obj)
{
	vector<string> *lpvStr = (vector<string> *)obj;
	return lpvStr->size();
}
char* idaapi idaListFilter_getlien(void *obj, ulong n, char* buf)
{
	vector<string> *lpvStr = (vector<string> *)obj;
	if(n == 0)
	{
		qstrncpy( buf, "Value", qstrlen("Value") + 1);
		
	}
	else
	{

		qstrncpy(buf, lpvStr->at(n - 1).c_str(), 1024);
		
		
	}
	return buf;
}

uint32 idaapi idaListComment_update(void *obj, uint32 n)
{
	vector<ListData> *lpvldData = (vector<ListData> *)obj;
	if(n < 1)
	{
		return lpvldData->size();
	}
	int i = VectorFind(lpvldData->at(n -1).strValue, ldFilterData);
	int nCount = 0;
	if(i < 0)
	{
		ldFilterData.push_back(lpvldData->at(n -1).strValue);
		i = ldFilterData.size();
	}
	
	int choi = choose((void*)&ldFilterData, 48, idaListFilter_sizer, idaListFilter_getlien, (char*)"过滤列表 点击OK 写入到配置文件中", -1, i , idaListFilter_delete);
//	msg("choi:%d\n", choi);
	if(choi > 0)
	{
		WriteFilterIni(g_szIniPath, ldFilterData);
	}
	lpvldData->clear();
	nCount = ldData.size();
	for(i = 0; i < nCount; i++)
	{
		if(VectorFind(ldData[i].strValue, ldFilterData) < 0)
		{
			lpvldData->push_back(ldData[i]);
		}
	}
	return 1;
}
void ListPush(ea_t dwAddr, char *lpStr, vector<ListData> &vldData)
{
	char szTmpBuf[0x200] = {0};
	int j = 0;
	int i = 0;
	int nlen = strlen(lpStr);
	for(i = 0; i < nlen; i++)
	{
		if(lpStr[i] == '\n')
		{
			szTmpBuf[j++] = '\\';
			szTmpBuf[j++] = 'n';
		}
		else
		{
			szTmpBuf[j++] = lpStr[i];
		}
	}
	ListData ldTmp;
	ldTmp.eaAddr = dwAddr;
	ldTmp.strValue = string(szTmpBuf);
	vldData.push_back(ldTmp);
}
int AddListData(func_t *f, vector<ListData> &vldData)
{
	int iRet = 0;
	ea_t dwAddr = f->startEA;
	int i = 0;
	int nlen;
	char szBuf[0x200] = {0};
	
	for(dwAddr = f->startEA; dwAddr < f->endEA; dwAddr = find_code(dwAddr, SEARCH_DOWN|SEARCH_NEXT))
	{
		memset(szBuf, 0, 0x200);
		if( (nlen = get_cmt(dwAddr, 0, szBuf, 0x200)) > 1 )
		{	
			if(memcmp("switch ", szBuf, strlen("switch ")))
			{
				ListPush(dwAddr, szBuf, vldData);
				iRet++;
			}
			
		}
		memset(szBuf, 0, 0x200);
		if( get_cmt(dwAddr, 1, szBuf, 0x200) > 1)
		{
			if(memcmp("jumptable", szBuf, strlen("jumptable")))
			{
				ListPush(dwAddr, szBuf, vldData);
				iRet++;
			}		
		}
	}
	return iRet;
}

int AddListData(vector<ListData> &vldData)
{
	int iRet = 0;
	ea_t dwAddr = 0, startaddr, endaddr;
	int i = 0;
	segment_t *curseg;
	int nlen;
	char szBuf[0x200] = {0};

	int seg_qty = get_segm_qty();
	if(seg_qty > 0)
	{
		curseg = getnseg(0);
		startaddr = curseg->startEA;
		endaddr = curseg->endEA - 1;
		for(i = 1; i < seg_qty; i++)
		{
			curseg = getnseg(i);
			if(isLoaded(curseg->endEA - 1) )// && SEG_CODE == curseg->type)
			{
				endaddr = curseg->endEA - 1;
			}
		}

	}

	for(dwAddr = startaddr; dwAddr < endaddr; dwAddr = find_code(dwAddr, SEARCH_DOWN|SEARCH_NEXT))
	{
		memset(szBuf, 0, 0x200);
		if( (nlen = get_cmt(dwAddr, 0, szBuf, 0x200)) > 1 )
		{	
			if(memcmp("switch ", szBuf, strlen("switch ")))
			{
				ListPush(dwAddr - startaddr, szBuf, vldData);
				iRet++;
			}

		}
		memset(szBuf, 0, 0x200);
		if( get_cmt(dwAddr, 1, szBuf, 0x200) > 1)
		{
			if(memcmp("jumptable", szBuf, strlen("jumptable")))
			{
				ListPush(dwAddr - startaddr, szBuf, vldData);
				iRet++;
			}		
		}
	}
	return iRet;
}

// 插件可以从plugins.cfg文件中，被传进一个整型参数。
// 当按下不同的热键或者菜单时，您需要一个插件做不同
// 的事情时，这非常有用。
void __stdcall IDAP_run(int arg)
{
	static const char *szBuf[] = {"pop1", "pop2", "pop3", "Add Filter List"};
	vector<ListData> ldTmpData;
	vector<string> vStr;
	ea_t *lpea_ts = NULL;
	ldData.clear();
	ldCommentData.clear();
	UINT32 i = 0;
	UINT32 j = 0;
	UINT32 nCount = get_func_qty();
//	for(i = 0; i < nCount; i++)
//	{
//		AddListData(getn_func(i), ldTmpData);
//	}
	AddListData(ldTmpData);
	/////////除虫
	nCount = ldTmpData.size();
	lpea_ts = (ea_t *)malloc(nCount * sizeof(ea_t));
	for (i = 0; i < nCount; i++)
	{
		string str = ldTmpData.at(i).strValue;
		if(VectorFind(str, vStr) < 0)
		{
			vStr.push_back(str);
			lpea_ts[j++] = ldTmpData.at(i).eaAddr;
		}
	}

	nCount = vStr.size();
	for(i = 0; i < nCount; i++)
	{
		ListData ldTmp;
		ldTmp.eaAddr = lpea_ts[i];
		ldTmp.strValue = vStr.at(i);
		ldData.push_back(ldTmp);
	}
	ldTmpData.clear();
	free(lpea_ts);
	//////////////
	nCount = ldData.size();
	for(i = 0; i < nCount; i++)
	{
		if(VectorFind(ldData[i].strValue, ldFilterData) < 0)
		{
			ldCommentData.push_back(ldData[i]);
		}
	}

	int choice = choose2(CH_MULTI, -1, -1, -1, -1,(void*)&ldCommentData, 2, (int*)widths, 
		idaListComment_sizer, idaListComment_getlien2, "Comment List", -1, 1, NULL, NULL, idaListComment_update, NULL, idaListComment_enter,
		NULL,(const char * const *)szBuf,NULL);
	if(choice > 0)
	{
		jumpto(ldCommentData[choice - 1].eaAddr);
	}
	
/*	nFuntionCount = ldData.size();
	for(i = 0; i < nFuntionCount; i++)
	{
		msg("Addr:0x%08X     Comment:%s\n", ldData[i].eaAddr, ldData[i].strValue.c_str());
	}
	ldData.clear();
	*/
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
char IDAP_name[] = "KDComment List";
// 启动插件的热键，纯字符的定义，比较易懂
char IDAP_hotkey[] = "Alt-;";
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