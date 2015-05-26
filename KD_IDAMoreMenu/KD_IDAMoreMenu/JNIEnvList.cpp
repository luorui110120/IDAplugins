#include "JNIEnvList.h"
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
#include <struct.hpp>
#include "JNIEnvData.h"

char g_headers[][256] = {"Index", "Offset", "FunName", "FunDefine"};
int g_widths[] = {3, 4,25,50};

ulong idaapi idaList_sizer(void *obj)
{
	//	vector<ListData> *lpvldData = (vector<ListData>*) obj;
	return sizeof(g_szFunNames)/sizeof(g_szFunNames[0]);
}
void idaapi idaList_getlien2(void *obj, ulong n, char* const *cells)
{
	int nsize = sizeof(g_szFunNames)/sizeof(g_szFunNames[0]);
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
		qsnprintf(cells[0], 0x100, "%X", n -1);
		qsnprintf(cells[1], 0x100, "%X", (n -1) * 4);
		qstrncpy(cells[2], g_szFunNames[n - 1], 1024);
		qstrncpy(cells[3], g_szFunDefins[n - 1], 1024);

	}
}
HINSTANCE open_WebURL(char *lpInBuf)
{
	char szTmpBuf[256] = {0};
	sprintf(szTmpBuf, "url.dll,FileProtocolHandler %s", lpInBuf);
	HINSTANCE result = ShellExecute(NULL, "open", "rundll32.exe", szTmpBuf, NULL, SW_SHOWNORMAL);	
	return result;
}
void idaapi idaList_enter(void * obj,uint32 n)
{
	char szTmpBuf[256] = {0};
	sprintf(szTmpBuf, "https://www.google.com.hk/search?q=%s", g_szFunNames[n - 1]);
	open_WebURL(szTmpBuf);
	msg("Google search:%s\n", g_szFunNames[n - 1]);
}
int ShowJNIEnvList()
{
	tid_t tid = get_struc_id ( "JNINativeInterface" ) ;
	struc_t * sptr = get_struc ( tid );
	int i = 0;
	if ( sptr == NULL )
	{
		tid = add_struc ( BADNODE,    "JNINativeInterface" ) ;
		sptr = get_struc ( tid );

		if ( sptr )
		{
			int nCount = sizeof(g_szFunNames) / sizeof(g_szFunNames[0]);
			for(i = 0; i < nCount; i++)
			{
				add_struc_member ( sptr, g_szFunNames[i], -1, dwrdflag(), NULL, 4 );
			}
		}
	}
	int choice = choose2(CH_MULTI, -1, -1, -1, -1, NULL, sizeof(g_widths) / sizeof(g_widths[0]), (int*)g_widths, 
		idaList_sizer, idaList_getlien2, "JNIEnv Funtion List", -1, 1, NULL, NULL, NULL, NULL, idaList_enter,
		NULL, NULL,NULL);
	return choice;
}