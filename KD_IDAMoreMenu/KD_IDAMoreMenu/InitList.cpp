#include <windows.h>
#include <Shlwapi.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <search.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <stdio.h>
#include <vector>
#include <string>
#include "InitData.h"



extern HINSTANCE open_WebURL(char *lpInBuf);

ulong idaapi idaInitTableList_sizer(void *obj)
{
	//	vector<ListData> *lpvldData = (vector<ListData>*) obj;
	return sizeof(szInitDeclare)/sizeof(szInitDeclare[0]);
}
void idaapi idaInitTableList_getlien2(void *obj, ulong n, char* const *cells)
{
	static char g_headers[][256] = {"Dec", "Hex", "FunName", "FunDefine"};
	int nsize = sizeof(szInitDeclare)/sizeof(szInitDeclare[0]);
	int i = 0;
	int nCells = sizeof(g_headers) / sizeof(g_headers[0]);
	if(n > nsize)
	{
		return;
	}
	if(n == 0)
	{
		for(i = 0; i < nCells; i++)
		{
			qstrncpy( cells[i], g_headers[i], qstrlen(g_headers[i]) + 1);
		}
	}
	else
	{
		qsnprintf(cells[0], 0x100, "%d", strtol(szInitIndex[n -1], NULL, 10));
		qsnprintf(cells[1], 0x100, "%X", strtol(szInitIndex[n -1], NULL, 10));
		qstrncpy(cells[2], szInitDeclare[n - 1], 1024);
		qstrncpy(cells[3], szFunDefine[n - 1], 1024);

	}
}


void idaapi idaInitTableList_enter(void * obj,uint32 n)
{
	char szTmpBuf[256] = {0};
	sprintf(szTmpBuf, "http://linux.die.net/man/2/%s", strstr(szInitDeclare[n - 1], "_NR_") + strlen("_NR_"));
	open_WebURL(szTmpBuf);
	msg("Google search:%s\n", szInitDeclare[n - 1]);
}
int ShowInitTableList()
{
	add_til2("armv12", 0);	//导入中断表 定义
	add_til2("gnuunx", 0);
	static int g_widths[] = {4, 3,25,125};
	int choice = choose2(CH_MULTI, -1, -1, -1, -1, NULL, sizeof(g_widths) / sizeof(g_widths[0]), (int*)g_widths, 
		idaInitTableList_sizer, idaInitTableList_getlien2, "Init Table List", -1, 1, NULL, NULL, NULL, NULL, idaInitTableList_enter,
		NULL, NULL,NULL);
	return choice;
}