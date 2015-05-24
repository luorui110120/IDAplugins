
#include "DlgMain.h"

#define HOTKEY_VALUE 0xB001

netnode n_asmbuf("$ disasm_buf", 0, true);
netnode n_asmoffset("$ disasm_offset", 0, true);
netnode n_asmaddr("$ disasm_addr", 0, true);
netnode n_asmtable("$ disasm_table", 0, true);
char *g_netnode_asmbuf;
unsigned int  *g_netnode_asmoffset;
unsigned int  *g_netnode_asmaddr;

unsigned int g_nbuflen , g_noffsetlen, g_naddrlen;
strbuftable g_sbt_table = {0};



HWND h_IDAMain = NULL;
char g_szHistoryBuf[4096] = "ldr   *\r\ncmp r0,*";

void DumpBufLog(char *pbuf, unsigned int len)
{
	unsigned int i = 0;
	for(i = 0; i < len; i++)
	{
		msg("%02X", pbuf[i]);
	}
	msg("\n");
}

int SaveNetnode(netnode &n, AUTO_BUFFER &auto_buf)
{
	unsigned int nCount = 0, i = 0;
	nCount = auto_buf.Size() / 0x400;
	for(i = 0; i < nCount; i++)
	{
		n.supset( NETNODE_START_INDEX + i, auto_buf.Get() + NETNODE_BUFFER_MAX * i, NETNODE_BUFFER_MAX);
	}
	if(auto_buf.Size() % 0x400)
	{
		n.supset( NETNODE_START_INDEX + i, auto_buf.Get() + NETNODE_BUFFER_MAX * nCount, auto_buf.Size() % NETNODE_BUFFER_MAX);
		nCount++;
	}
	return nCount;
}
// 返回 数据 大小
unsigned int GetNetnode(netnode &n, unsigned int nCount, void** pp)
{
	unsigned int i = 0;
	unsigned int dwRet = nCount * NETNODE_BUFFER_MAX;
	if(nCount)
	{
		*pp = MALLOC(nCount * NETNODE_BUFFER_MAX + 1);
		for(i = 0; i < nCount; i++)
		{
			n.supval(NETNODE_START_INDEX + i, (char*)*pp + i * NETNODE_BUFFER_MAX, NETNODE_BUFFER_MAX);
		}
		if(n.supval(NETNODE_START_INDEX + nCount - 1, NULL, 0) != NETNODE_BUFFER_MAX)
		{
			dwRet = dwRet - NETNODE_BUFFER_MAX + n.supval(NETNODE_START_INDEX + nCount - 1, NULL, 0);
		}
	}
	return dwRet;
}
int getLineBuf(char *pbuf, char *pout)
{
	int i = 0, iret = 0, j = 0;
	if(*pbuf != '\n')
	{
		while(*(pbuf + i) != '\n')
		{
			i--;
		}
	}
	i++;
	iret = i;
	while(pbuf[i] && pbuf[i] != '\n')
	{
		pout[j] = pbuf[i];
		j++;
		i++;
	}
	pout[j] = 0;
	return iret;
}
DWORD WINAPI  CreateCodeSnapshoot(LPVOID lpParameter)
{
	HWND hwnd = (HWND)lpParameter;
	AUTO_BUFFER auto_asmbuf(0x1000);
	AUTO_BUFFER auto_asmoffset(0x1000);
	AUTO_BUFFER auto_asmaddr(0x1000);
	vector<strbufindex> m_VectorIndex;
	int nSendPlan = 0;

	unsigned int i, nCount, nAsmlen = 0;
	segment_t *curseg;
	ea_t startaddr, endaddr, iaddr, iAddrRange;
	char *lpSavePath;
	FILE *f = NULL;
	char szbuf[256] = {0};
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
//	msg("startAddr: %08x,  end:%08X\n", startaddr, endaddr);
	iAddrRange = endaddr - startaddr;
	//	endaddr =0x8A100 - 5;
	long ntime = GetTickCount();
	iaddr = startaddr;
	auto_asmbuf.Put("\n", strlen("\n"));
	while(iaddr < endaddr)
	{
		strbufindex vectorTmp;
		memset(szbuf, 0, sizeof(szbuf));
		generate_disasm_line(iaddr, szbuf, sizeof(szbuf));
		tag_remove(szbuf, szbuf, 0);
		if(szbuf[0])
		{
			vectorTmp.dwbufoffset = auto_asmbuf.Size();
			vectorTmp.dwasmaddr = iaddr - startaddr;
			m_VectorIndex.push_back(vectorTmp);
		}
		iaddr = find_code(iaddr, SEARCH_DOWN | SEARCH_NEXT);
		FilterSpacing(szbuf);
		auto_asmbuf.Put(szbuf, strlen(szbuf));
		auto_asmbuf.Put("\n", strlen("\n"));
		if((vectorTmp.dwasmaddr * 100 / iAddrRange) > nSendPlan )
		{
			nSendPlan = vectorTmp.dwasmaddr * 100 / iAddrRange;
			if(IsWindow(hwnd))
			{
			//	Sleep(500);
				SendMessage(hwnd, WM_CREATE_SHAPSHOOT, (WPARAM)nSendPlan, NULL);
			}
			else
			{
				return -1;
			}
		}
		//	if(iaddr >= 0x8F518 && iaddr != 0xFFFFFFFF)
		//	{

		//		msg("%s,  startaddr: 0x%x\n", szbuf,iaddr );
		//	}
	}
	g_sbt_table.dwBufArrayCount = SaveNetnode(n_asmbuf, auto_asmbuf);
	g_nbuflen = auto_asmbuf.Size();
	nCount = m_VectorIndex.size();
	for(i = 0; i < nCount; i++)
	{
		auto_asmoffset.Put((char*) &m_VectorIndex.at(i).dwbufoffset, sizeof(unsigned int));
		auto_asmaddr.Put((char*) &m_VectorIndex.at(i).dwasmaddr, sizeof(unsigned int));
	}
	g_sbt_table.dwOffsetArrayCount = SaveNetnode(n_asmoffset, auto_asmoffset);
	g_sbt_table.dwAddrArrayCount = SaveNetnode(n_asmaddr, auto_asmaddr);
	g_naddrlen = auto_asmaddr.Size() / sizeof(unsigned int);
	g_noffsetlen = auto_asmoffset.Size() / sizeof(unsigned int);
	GetCurrentDate((char*)g_sbt_table.szDate,  sizeof(g_sbt_table.szDate));
	n_asmtable.supset(1000, &g_sbt_table, sizeof(g_sbt_table));

	if(IsWindow(hwnd))
	{
		SendMessage(hwnd, WM_CREATE_SHAPSHOOT, (WPARAM)100, NULL);
	}
	else
	{
		return -1;
	}
	//msg("time-consuming: %d sec, abuf.size:0x%08X, Current time: %s\n", (GetTickCount() - ntime) / 100, auto_asmbuf.Size(), g_sbt_table.szDate);
	//给全局赋值
	g_netnode_asmbuf = (char*) MALLOC(auto_asmbuf.Size() + 1);
	memcpy(g_netnode_asmbuf, auto_asmbuf.Get(), auto_asmbuf.Size());
	g_netnode_asmoffset = (unsigned int*) MALLOC(auto_asmoffset.Size() + 1);
	memcpy(g_netnode_asmoffset, auto_asmoffset.Get(), auto_asmoffset.Size());
	g_netnode_asmaddr = (unsigned int*) MALLOC(auto_asmaddr.Size() + 1);
	memcpy(g_netnode_asmaddr, auto_asmaddr.Get(), auto_asmaddr.Size());

	return 0;
}
void  CreateThreadNewSnapshoot(HWND hwnd)
{
	HANDLE handle=::CreateThread(NULL,0, CreateCodeSnapshoot,(LPVOID)hwnd,0,NULL);  //创建线程
	//ThreadProcWritedb是回调函数    this传送的参数
	CloseHandle(handle); 
}
BOOL WINAPI Main_Proc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch(uMsg)
	{
		HANDLE_MSG(hWnd, WM_INITDIALOG, Main_OnInitDialog);
		HANDLE_MSG(hWnd, WM_COMMAND, Main_OnCommand);
		HANDLE_MSG(hWnd,WM_CLOSE, Main_OnClose);
		HANDLE_MSG(hWnd,WM_HOTKEY, Main_HotKey);
		case WM_CREATE_SHAPSHOOT:
			Main_OnCreateSnapshootPlan(hWnd, wParam, lParam);
			break;
		
	}
	

	return FALSE;
}

BOOL Main_OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam)
{
	char szTmpBuf[256] = {0};
	POINT p;
	GetCursorPos(&p);
	RECT rect;
	GetWindowRect(hwnd,&rect);   //rect保存窗口大小
	MoveWindow(hwnd, p.x, p.y, rect.right - rect.left, rect.bottom - rect.top, TRUE);
	///////枚举所有函数
	// 	int nFunSum = get_func_qty();
	// 	g_FunInfoCount = nFunSum;
	// 	g_FunInfo = (structFunInfo *)malloc(nFunSum * sizeof(structFunInfo));
	// 	memset(g_FunInfo, 0, nFunSum * sizeof(structFunInfo));
	// 	int i = 0;
	// 	char szFunNameBuf[256] = {0};
	// 	for(i = 0; i < nFunSum; i++)
	// 	{
	// 		func_t *curFunc = getn_func(i);
	// 		get_func_name(curFunc->startEA, g_FunInfo[i].szName, 256);
	// 		g_FunInfo[i].dwAddr = curFunc->startEA;
	// 	}
	//	GetCurrentDirectory(256, szCurrentBuf);
	//	MessageBox(NULL, g_szReleasePath, NULL, 0);
	if( n_asmtable.supval(1000, &g_sbt_table, sizeof(g_sbt_table)) >= 0)
	{
		if (!(g_netnode_asmbuf && g_netnode_asmoffset && g_netnode_asmaddr))
		{
			g_nbuflen = GetNetnode(n_asmbuf, g_sbt_table.dwBufArrayCount, (void**)&g_netnode_asmbuf);
			g_noffsetlen = GetNetnode(n_asmoffset, g_sbt_table.dwOffsetArrayCount, (void**)&g_netnode_asmoffset) / sizeof(unsigned int);
			g_naddrlen = GetNetnode(n_asmaddr, g_sbt_table.dwAddrArrayCount, (void**)&g_netnode_asmaddr) / sizeof(unsigned int);
			//ShowState(hwnd, "nbuflen: 0x%08X, noffsetlen: 0x%08X, naddrlen: 0x%08X, Date: %s\n", g_nbuflen, g_noffsetlen, g_naddrlen, g_sbt_table.szDate);
		}
		ShowState(hwnd, "Current snapshoot Create Date: %s\n", g_sbt_table.szDate);
		//SendMessage(GetDlgItem(hwnd, IDC_RADIO_CURRENT), BM_SETCHECK, 1, 0);
		SelectRadio(hwnd, IDC_RADIO_CURRENT);
	}
	else
	{
		ShowState(hwnd, "%s","当前无 代码快照");
		//SendMessage(GetDlgItem(hwnd, IDC_RADIO_CURRENT), BM_SETCHECK, 0, 0);
		SelectRadio(hwnd, IDC_RADIO_CREATE);
		CreateThreadNewSnapshoot(hwnd);
		EnableWindow(GetDlgItem(hwnd,IDC_BUTTON_ENTER), FALSE);
	}
	SetDlgItemText(hwnd, IDC_EDIT_INCODE, g_szHistoryBuf);		//测试
	UnregisterHotKey(hwnd, HOTKEY_VALUE);
	RegisterHotKey(hwnd, HOTKEY_VALUE ,MOD_CONTROL, VK_RETURN );
	return TRUE;
}
BOOL Main_HotKey(HWND hwnd, int nId, WPARAM wParam, LPARAM lParam)
{
	if(nId == HOTKEY_VALUE)
	{
		OnButtonFind(hwnd);
		return TRUE;
	}
	return FALSE;
}
void Main_OnCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify)
{
	switch(id)
	{
	case IDC_BUTTON_ENTER:
		{
			OnButtonFind(hwnd);
		}
		break;
	case IDC_BUTTON_CANCEL:
		{
			Main_OnClose(hwnd);
		}
		break;
		//	case 1001:
	default:
		break;
	}
}

void Main_OnClose(HWND hwnd)
{
	UnregisterHotKey(hwnd, HOTKEY_VALUE);
	//	free(g_FunInfo);
	SetForegroundWindow(h_IDAMain);
	DestroyWindow(hwnd);

}
void Main_OnCreateSnapshootPlan(HWND hwnd, WPARAM wParam, LPARAM lParam)
{
	if(100 == (int)wParam)
	{
		EnableWindow(GetDlgItem(hwnd, IDC_BUTTON_ENTER), TRUE);
		ShowState(hwnd, "Current snapshoot Create Date: %s\n", g_sbt_table.szDate);
	//	SendMessage(GetDlgItem(hwnd, IDC_RADIO_CURRENT), BM_SETCHECK, 1, 0);
		SelectRadio(hwnd, IDC_RADIO_CURRENT);
	}
	else
	{
		ShowState(hwnd, "Create snapshoot schedule %d%%\n", (int )wParam);
	}
}
BOOL CALLBACK EnumWindowsProc(
	HWND hwnd,      // handle to parent window
	LPARAM lParam   // application-defined value
	)
{
	DWORD PID;
	BOOL  Result=TRUE;
	GetWindowThreadProcessId(hwnd,&PID);
	if (PID=GetCurrentProcessId())
	{
		char szBuf[256] = {0};
		GetClassName(hwnd, szBuf,256);
		if(strcmp("QWidget", szBuf) == 0)
		{
			h_IDAMain = hwnd;//这个g_hwin在你的DLL里定义为一个全局的HWND,也是你想要的句柄
			Result = FALSE;
		}
	}
	return Result;
}
void OnButtonFind(HWND hwnd)
{
	char szparent[4096] = {0};
	if(GetDlgItemText(hwnd, IDC_EDIT_INCODE, szparent, sizeof(szparent)) <= 0)
	{
		ShowState(hwnd, "%s","请输入指令!");
		return;
	}
	else
	{
		strncpy(g_szHistoryBuf, szparent, sizeof(g_szHistoryBuf));
	}
	strupr(szparent);
	FilterSpacing(szparent);
	unsigned int nBufIndex = 0;
	unsigned int nOffsetIndex = 0;
	segment_t *curseg;
	ea_t startaddr;
	if( n_asmtable.supval(1000, &g_sbt_table, sizeof(g_sbt_table)) < 0 || SendMessage (GetDlgItem(hwnd, IDC_RADIO_CREATE), BM_GETCHECK, 0, 0))
	{
		EnableWindow(GetDlgItem(hwnd, IDC_BUTTON_ENTER), FALSE);
		CreateThreadNewSnapshoot(hwnd);
		return;
	}
	
	curseg = getnseg(0);
	if(curseg)
	{
		
		unsigned int dwasmbufOffset = 0, dwtmpOffset= 0;
		startaddr = curseg->startEA;
		int i = 0;
	//	char szparent[] = "LDR*\nCMPR0,*";
		char *pszSearch = (char *)MALLOC(strlen(szparent) + 1);
	//	msg("startaddr : 0x%08X\n", startaddr);
	/*	int tmp2 = 0;
		while( (nBufIndex = KMP(g_netnode_asmbuf + dwtmpBuf, "BLabort\n")) != 0xFFFFFFFF
			&& dwtmpBuf < g_nbuflen && dwtmpOffset < g_naddrlen )
		{
			dwtmpBuf += nBufIndex;
			nOffsetIndex = DichotomySearch(g_netnode_asmoffset + dwtmpOffset, g_noffsetlen - dwtmpOffset, dwtmpBuf);
			msg("find addr: 0x%08X \n", g_netnode_asmaddr[nOffsetIndex + dwtmpOffset] + startaddr);
			dwtmpOffset += nOffsetIndex;
			dwtmpBuf++;
			//break;
		}
		*/
		vector<string> vSearchCodes = tokenize(string(szparent), string("\r\n"), false);
		msg("============开始搜索=============\n");
		msg("搜索数据:\n%s\n", szparent);
		for(i = 0; !pszSearch[0] && i<vSearchCodes.size();i++)  
		{  
			const char *p = vSearchCodes[i].c_str();
			if(p[0] == '*' && p[1] == 0)
			{
				continue;
			}
		//	msg("%s\n",vSearchCodes[i].c_str());  
			if(strchr(p, '*'))
			{
				int j = 0,k=0, len = strlen(p);
				for(j = 0; j < len; j++)
				{
					if(p[j] != '*')
					{
						pszSearch[k++] = p[j];
					}
					else if(k)
					{
						break;
					}
				}
			}
			else
			{
				strcpy(pszSearch, p);
			}
		}
		if(0 == pszSearch[0])
		{
			ShowState(hwnd, "%s","非法指令!\n");
			FREE(pszSearch);
			return;
		}
	//	trim(pszSearch);
	//	msg("pszSearch:%s\n", pszSearch);
		i--;
		while( (dwasmbufOffset = FindingString(g_netnode_asmbuf, pszSearch, dwasmbufOffset)) != 0xFFFFFFFF )
		{
			char szOutBuf[256] = {0};
			int findoffset = dwasmbufOffset;
			findoffset += getLineBuf(g_netnode_asmbuf + dwasmbufOffset, szOutBuf);
			char *p = g_netnode_asmbuf + findoffset;
			int nj = 0;
			int j = i;
			dwasmbufOffset++;
			
			for(j = i; j < vSearchCodes.size(); j++)
			{
				if(!MatchingString(szOutBuf, vSearchCodes[j].c_str(), false))
				{
					break;
				}
				nj += strlen(szOutBuf) + 1;
				if(p[nj])		//判断是否已经到 缓冲区末尾
				{
					nj += getLineBuf(p + nj , szOutBuf);
				}
				else
				{
					j++;
					break;
				}
			}
			
			if(j == vSearchCodes.size())
			{
				nOffsetIndex = DichotomySearch(g_netnode_asmoffset, g_noffsetlen, findoffset, nOffsetIndex);
				if(nOffsetIndex != 0xFFFFFFFF)
				{
					msg("find success addr: 0x%08X\n", g_netnode_asmaddr[nOffsetIndex] + startaddr);
					dwasmbufOffset = findoffset;
					for(j = i; j < vSearchCodes.size(); j++)
					{
						dwasmbufOffset += getLineBuf(g_netnode_asmbuf + dwasmbufOffset, szOutBuf);
						dwasmbufOffset += strlen(szOutBuf) + 1;
					}
				}
				
			//	break;
			}
		}
		FREE(pszSearch);
	}
	msg("============搜索结束=============\n");
	Main_OnClose(hwnd);
}
int  ShowState(HWND hwnd, const char *format,... )
{
	char szbuf[4096] = {0};
	va_list   args; 
	va_start(args,format); 
	vsprintf(szbuf, format,args);   
	va_end(args);
	SetDlgItemText(hwnd, IDC_STATIC_STATE, szbuf);
	return strlen(szbuf);
}
int SelectRadio(HWND hwnd, int nIDDlgItem)
{
	return SendMessage(GetDlgItem(hwnd, nIDDlgItem), BM_CLICK, 0, 0);
}