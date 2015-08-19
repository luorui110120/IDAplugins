#include <windows.h>
#include <vector>
#include "DlgMain.h"
using namespace std;
extern char g_szReleasePath[256];
int g_nType = 0;
#define HOTKEY_VALUE 0xB001
#ifdef __EA64__
#define CODE_OFFSET 0x40
#else
#define CODE_OFFSET 0x34
#endif
unsigned char const g_StaticData[82] = {
	0x2E, 0x67, 0x6C, 0x6F, 0x62, 0x6C, 0x20, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x0A, 0x2E, 0x61, 
	0x6C, 0x69, 0x67, 0x6E, 0x20, 0x32, 0x0A, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x3A, 0x0A, 0x2E, 
	0x63, 0x6F, 0x64, 0x65, 0x20
};
typedef struct _LocalVarilInfo
{
	char szName[256];
	ea_t dwAddr;
}LocalVarilInfo;
 vector<LocalVarilInfo> g_lvInfos;
// int g_FunInfoCount = 0;
ea_t g_Current = 0;
DWORD g_nCodeLen = 0;
HWND h_IDAMain = NULL;
BOOL WINAPI Main_Proc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static BOOL nFlasKey[VK_RETURN + 1] = {0};
	switch(uMsg)
	{
		HANDLE_MSG(hWnd, WM_INITDIALOG, Main_OnInitDialog);
		HANDLE_MSG(hWnd, WM_COMMAND, Main_OnCommand);
		HANDLE_MSG(hWnd,WM_CLOSE, Main_OnClose);
		HANDLE_MSG(hWnd,WM_HOTKEY, Main_HotKey);
		if(uMsg == WM_KEYDOWN)
		{
				msg("WM_KEYDOWN: %X\n", wParam);
				if(wParam == VK_CLEAR || wParam == VK_RETURN)
				{
					nFlasKey[wParam] = TRUE;
					if(nFlasKey[VK_CLEAR] && nFlasKey[VK_RETURN])
					{
						msg("jinru Patch Arm\n");
						//OnButtonCalc(hWnd);
						nFlasKey[VK_CLEAR] = FALSE;
						nFlasKey[VK_RETURN] = FALSE;
						return TRUE;
					}
				}
		}
		else if(uMsg == WM_KEYUP)
		{
			if(wParam == VK_CLEAR || wParam == VK_RETURN)
			{
				nFlasKey[wParam] = FALSE;
			}
		}
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

	g_Current = get_screen_ea();
	///////枚举所有局部变量
	func_t *funV = get_func(g_Current);
	if(funV)
	{
		ea_t startAddr = funV->startEA;
		ea_t EndAddr = funV->endEA;
		ea_t i = startAddr;
 		while(i < EndAddr)
		{
			LocalVarilInfo lviTmp = {0};
			get_name(i, i, lviTmp.szName, sizeof(lviTmp.szName));
			if(strlen(lviTmp.szName) > 0)
			{
				lviTmp.dwAddr = i;
				g_lvInfos.push_back(lviTmp);
			}
			i = find_code(i, SEARCH_DOWN | SEARCH_NEXT);
		}
	}
	

#ifdef __EA64__
	ShowWindow(GetDlgItem(hwnd, IDC_RADIO_ARM), SW_HIDE);
	ShowWindow(GetDlgItem(hwnd, IDC_RADIO_THUMB), SW_HIDE);
	sprintf(szTmpBuf, "%I64X", g_Current);
#else
	g_nType = getSR(g_Current, str2reg("T"));
	if(g_nType == 0)
	{

		SendMessage(FindWindowEx(hwnd, NULL, "Button", "ARM"), BM_SETCHECK, 1, 0);
	}
	else
	{
		SendMessage(FindWindowEx(hwnd, NULL, "Button", "THUMB"), BM_SETCHECK, 1, 0);
	}
	sprintf(szTmpBuf, "%08X", g_Current);
#endif
	SetDlgItemText(hwnd, IDC_EDIT_ADDR, szTmpBuf);
//	GetCurrentDirectory(256, szCurrentBuf);
//	MessageBox(NULL, g_szReleasePath, NULL, 0);
	UnregisterHotKey(hwnd, HOTKEY_VALUE);
	RegisterHotKey(hwnd, HOTKEY_VALUE ,MOD_CONTROL, VK_RETURN );
	return TRUE;
}
BOOL Main_HotKey(HWND hwnd, int nId, WPARAM wParam, LPARAM lParam)
{
	if(nId == HOTKEY_VALUE)
	{
		OnButtonCalc(hwnd);
		return TRUE;
	}
	return FALSE;
}
void Main_OnCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify)
{
	switch(id)
	{
	case IDC_OK:
		{
			OnButtonCalc(hwnd);
		}
		break;
	case IDC_CANCEL:
		{
			Main_OnClose(hwnd);
		}
		break;
//	case 1001:
	default:
		break;
	}
}
void SetArmColor(DWORD addr, DWORD len, int nType, bgcolor_t dwColor)
{
	int nloop = len / (( 2 - nType) * 2);
	int i = 0;
	for(i = 0; i < nloop; i++)
	{
		set_item_color(addr + i * (( 2 - nType) * 2), dwColor);
	}
}
void Main_OnClose(HWND hwnd)
{
	UnregisterHotKey(hwnd, HOTKEY_VALUE);
//	free(g_FunInfo);
	g_lvInfos.clear();
	SetForegroundWindow(h_IDAMain);
	DestroyWindow(hwnd);
// 	if(g_nCodeLen > 0)
// 	{
// 
// 		bgcolor_t color = get_item_color(g_Current);
// 		SetArmColor(g_Current, g_nCodeLen, g_nType, 0xFF00FF);
// 		Sleep(3000);
// 		SetArmColor(g_Current, g_nCodeLen, g_nType, color);
// 		g_nCodeLen = 0;
// 	}
	
}

DWORD GetDesAddr(char *lpInBuf, vector<LocalVarilInfo> &vlviDatas)
{
	const char szTable[]= "0123456789abcdefx";
	BOOL bFlags = FALSE;
	char szBuf[256] = {0};
	int nSaveIndexs[50] = {0};
	int nSaveSum = 0;
	int i = 0;
	int j = 0;
	int k = 0;
	int len =strlen(lpInBuf);
	/////////获得空格 和Tab
	for(i = 0; i < len; i++)
	{
		if( (lpInBuf[i] != 0x20) && (lpInBuf[i] != 0x9) )
		{
			if(lpInBuf[i] >=0x41 && lpInBuf[i] <=0x5A)
			{
				nSaveIndexs[nSaveSum] = j;	//记录被转化的大写字符索引
				nSaveSum++;
				szBuf[j++] = lpInBuf[i] + 0x20;
			}
			else
			{
				szBuf[j++] = lpInBuf[i];
			}
		}
	}
	int nTableLen = strlen(szTable);
	//////判断 是否为字符串 而非地址
	for(i = 0; i < j; i++)
	{
		for(k = 0; k < nTableLen; k++)
		{
			if(szBuf[i] == szTable[k])
			{
				break;
			}
		}
		if(k == nTableLen)
		{
			break;
		}
	}
	if(i != j)
	{
		////////还原函数名称大小写
		for(i = 0; i < nSaveSum; i++)
		{
			szBuf[nSaveIndexs[i]] -= 0x20;
		}
		///////////查找对应的函数地址
		int nCount = vlviDatas.size();
		for(i = 0; i < nCount; i++)
		{
			LocalVarilInfo lviTmp = vlviDatas.at(i);
			if(0 == strcmp(szBuf, lviTmp.szName) )
			{
				return lviTmp.dwAddr;
			}
		}
		return get_name_ea(-1, szBuf);
//		return -1;
	}
	else
	{
		return strtoul(szBuf, NULL, 16);
	}
}
#ifdef __EA64__
int AnalyzerStr(char *lpInData, ea_t dwCurrentAddr, char *lpOutBuf, BLArray *lpBLCountBuf, int &nCount)
{
	vector<LocalVarilInfo> vlviTmp;
	char *p = NULL;
	int j = 0;
	int i = 0;
	int sum = 0;		//记录汇编指令
	int nVectorSize = g_lvInfos.size();
	for(i = 0; i < nVectorSize; i++)
	{
		vlviTmp.push_back(g_lvInfos.at(i));
	}
	for(p = strtok(lpInData, "\r\n"); p != NULL; p = strtok(NULL, "\r\n"), sum++)
	{

		for(i = 0; p[i]; i++)
		{
			if(p[i] != 0x20 && p[i] != 0x9)
			{
				break;
			}
		}
		if(p[i] == 0)
		{
			continue;
		}
		if(strchr(&p[i], ':'))
		{
			strcpy(lpOutBuf + j , p + i);
			j += strlen(p + i);
			lpOutBuf[j++] = 0xA;
			LocalVarilInfo lviTmp = {0};
			strcpy(lviTmp.szName, p + i);
			*strchr(lviTmp.szName, ':') = 0;
			lviTmp.dwAddr = sum * 2  * 2 + dwCurrentAddr;
			vlviTmp.push_back(lviTmp);
			sum--;
			continue;
		}
		if( p[i] == 0x42 || p[i] == 0x62)
		{
			////////////////////判断是否为  BL r4   这种指令
			char szBuf[256] = {0};
			char *lpInBuf = p + i;
			int nLooplen = strlen(lpInBuf);
			int ii = 0;
			int jj = 0;
			////将大写转小写
			for(ii = 0; ii < nLooplen; ii++)
			{
				if( (lpInBuf[ii] != 0x20) && (lpInBuf[ii] != 0x9) )
				{
					if(lpInBuf[ii] >='A' && lpInBuf[ii] <= 'Z')
					{
						szBuf[jj++] = lpInBuf[i + ii] + 0x20;		
					}
					else
					{
						szBuf[jj++] = lpInBuf[i + ii];
					}
				}
				else
				{
					break;
				}
			}
			if(szBuf[1] == 'r' || szBuf[2] == 'r')
			{
				strcpy(lpOutBuf + j , p + i);
				j += strlen(p + i);
				lpOutBuf[j++] = 0xA;
				continue;
			}

			///////////////////////////////
			lpBLCountBuf[nCount].nARMOffset = sum * 2  * 2;
			lpBLCountBuf[nCount].dwSrc = lpBLCountBuf[nCount].nARMOffset + dwCurrentAddr;
			strcpy(lpBLCountBuf[nCount].lpRod, p + i);
			nCount++;
			lpOutBuf[j++] = 'n';
			lpOutBuf[j++] = 'o';
			lpOutBuf[j++] = 'p';
		}
		else
		{

			strcpy(lpOutBuf + j , p + i);
			j += strlen(p + i);
		}
		lpOutBuf[j++] = 0xA;

	}
	for(i = 0; i < nCount; i++)
	{
		lpBLCountBuf[i].dwDes = GetDesAddr(strchr(lpBLCountBuf[i].lpRod,' '), vlviTmp);//strtoul(strchr(p + i,' '), NULL, 16);
		//memcpy(lpBLCountBuf[nCount].lpRod, p + i,strchr(p + i,' ') - p - i);
		*strchr(lpBLCountBuf[i].lpRod, ' ') = 0;
	}
	vlviTmp.clear();
	return j;
}

#else
int AnalyzerStr(char *lpInData, ea_t dwCurrentAddr, char *lpOutBuf, BLArray *lpBLCountBuf, int &nCount)
{
	vector<LocalVarilInfo> vlviTmp;
	char *p = NULL;
	int j = 0;
	int i = 0;
	int sum = 0;
	int nVectorSize = g_lvInfos.size();
	for(i = 0; i < nVectorSize; i++)
	{
		vlviTmp.push_back(g_lvInfos.at(i));
	}
	for(p = strtok(lpInData, "\r\n"); p != NULL; p = strtok(NULL, "\r\n"), sum++)
	{
		
		for(i = 0; p[i]; i++)
		{
			if(p[i] != 0x20 && p[i] != 0x9)
			{
				break;
			}
		}
		if(p[i] == 0)
		{
			continue;
		}
		if(strchr(&p[i], ':'))
		{
			strcpy(lpOutBuf + j , p + i);
			j += strlen(p + i);
			lpOutBuf[j++] = 0xA;
			LocalVarilInfo lviTmp = {0};
			strcpy(lviTmp.szName, p + i);
			*strchr(lviTmp.szName, ':') = 0;
			lviTmp.dwAddr = sum * (2 - g_nType) * 2 + dwCurrentAddr;
			vlviTmp.push_back(lviTmp);
			sum--;
			continue;
		}
		if( p[i] == 0x42 || p[i] == 0x62)
		{
			////////////////////判断是否为  BL r4   这种指令
			static char szFilterRegTables[][20] = {"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "sp", "lr", "r10", "r11", "r12"};
			char szBuf[256] = {0};
			char *lpInBuf = strchr(p + i, ' ') + 1;
			int nLooplen = strlen(lpInBuf);
			int ii = 0;
			int jj = 0;
			for(ii = 0; ii < nLooplen; ii++)
			{
				if( (lpInBuf[ii] != 0x20) && (lpInBuf[ii] != 0x9) )
				{
					if(lpInBuf[ii] >=0x41 && lpInBuf[ii] <=0x5A)
					{
						szBuf[jj++] = lpInBuf[i] + 0x20;
					}
					else
					{
						szBuf[jj++] = lpInBuf[i];
					}
				}
			}
			if(jj > 1 && jj < 4)
			{
				nLooplen = sizeof(szFilterRegTables) / sizeof(szFilterRegTables[0]);
				for(ii = 0; ii < nLooplen; ii++)
				{
					if(0 == strcmp(szBuf, szFilterRegTables[i]))
					{
						break;
					}
				}
				if(ii == nLooplen)
				{
					strcpy(lpOutBuf + j , p + i);
					j += strlen(p + i);
					lpOutBuf[j++] = 0xA;
					continue;
				}
			}
			///////////////////////////////
			lpBLCountBuf[nCount].nARMOffset = sum * (2 - g_nType) * 2;
			lpBLCountBuf[nCount].dwSrc = lpBLCountBuf[nCount].nARMOffset + dwCurrentAddr;
			strcpy(lpBLCountBuf[nCount].lpRod, p + i);
			nCount++;
			lpOutBuf[j++] = 'n';
			lpOutBuf[j++] = 'o';
			lpOutBuf[j++] = 'p';
			if( g_nType && (p[i + 1] == 0x4C ||p[i + 1] == 0x6C))
			{
				sum++;
				lpOutBuf[j++] = '\n';
				lpOutBuf[j++] = 'n';
				lpOutBuf[j++] = 'o';
				lpOutBuf[j++] = 'p';
			}
		}
		else
		{

			strcpy(lpOutBuf + j , p + i);
			j += strlen(p + i);
		}
		lpOutBuf[j++] = 0xA;

	}
	for(i = 0; i < nCount; i++)
	{
		lpBLCountBuf[i].dwDes = GetDesAddr(strchr(lpBLCountBuf[i].lpRod,' '), vlviTmp);//strtoul(strchr(p + i,' '), NULL, 16);
		//memcpy(lpBLCountBuf[nCount].lpRod, p + i,strchr(p + i,' ') - p - i);
		*strchr(lpBLCountBuf[i].lpRod, ' ') = 0;
	}
	vlviTmp.clear();
	return j;
}
#endif
TCHAR* MyWinExec(TCHAR *lpIncmd, TCHAR *lpOutBuf, int nLen)
{
	SECURITY_ATTRIBUTES sa;
	HANDLE hRead,hWrite;

	sa.nLength = sizeof(SECURITY_ATTRIBUTES); 
	sa.lpSecurityDescriptor = NULL;   //使用系统默认的安全描述符 
	sa.bInheritHandle = TRUE;   //创建的进程继承句柄

	if (!CreatePipe(&hRead,&hWrite,&sa,0))   //创建匿名管道
	{  
		//		MessageBox(NULL,"CreatePipe Failed!","提示",MB_OK | MB_ICONWARNING);  
		return NULL;
	}

	STARTUPINFO si; 
	PROCESS_INFORMATION pi;

	ZeroMemory(&si,sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO); 
	GetStartupInfo(&si); 
	si.hStdError = hWrite; 
	si.hStdOutput = hWrite;   //新创建进程的标准输出连在写管道一端
	si.wShowWindow = SW_HIDE;   //隐藏窗口 
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;


	char cmdline[256] = {0}; 
	sprintf(cmdline,"cmd /C %s",lpIncmd);

	if (!CreateProcess(NULL,cmdline,NULL,NULL,TRUE,NULL,NULL,NULL,&si,&pi))   //创建子进程
	{ 
		return NULL;
	}
	CloseHandle(hWrite);   //关闭管道句柄

	char buffer[4096] = {0};
	//	CString strOutput;
	DWORD bytesRead;
	int sum = 0;
	while (true) 
	{
		if (ReadFile(hRead,buffer,4095,&bytesRead,NULL) == NULL)   //读取管道
			break;
		if(lpOutBuf && (sum < nLen))
		{
			memcpy(lpOutBuf + sum,buffer,bytesRead);
		}
		sum += bytesRead;
		memset(buffer,0,4096);
		Sleep(100);
	}
	CloseHandle(hRead);
	if(! lpOutBuf)
	{
		return (TCHAR*)0x1;
	}
	return lpOutBuf ;
}
BOOL MapFile(LPCTSTR lpFilePath,TCHAR *lpOutBuf, DWORD &dwCodeLen)
{
	dwCodeLen = 0;
	///////////////////////////读取文件
	HANDLE hFile=CreateFile(lpFilePath, GENERIC_WRITE | GENERIC_READ, 0, 
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);   //获得文件句柄
	if(hFile == (HANDLE)-1)
	{
		return false;
	}
	HANDLE hMapping=CreateFileMapping(hFile,NULL,PAGE_READWRITE,0,0,NULL);  //创建内存映射对象
	if(hMapping == (HANDLE)-1)
	{
		return false;
	}
	DWORD nFileSize  = GetFileSize(hFile, NULL) - CODE_OFFSET;
	PVOID pvFile=MapViewOfFile(hMapping,FILE_MAP_ALL_ACCESS,0,0,0); //创建视图 就是映射文件到内存
	PSTR lpCode=(PSTR)pvFile + CODE_OFFSET;
	//	MessageBox(hwnd,pvANSI,NULL,NULL);
	const unsigned char maic[] = {
		0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0xFF, 0xFF, 0xFF, 0xFF
	};
	for(dwCodeLen = 0; dwCodeLen < nFileSize; dwCodeLen++)
	{
		if(memcmp(maic, lpCode + dwCodeLen, sizeof(maic)) == 0)
		{
			break;
		}
	}
	memcpy(lpOutBuf,lpCode, dwCodeLen);
	UnmapViewOfFile(pvFile);
	CloseHandle(hMapping);
	CloseHandle(hFile);
	return true;
}

void WriteSrcFile(LPCTSTR lpInData)
{
	TCHAR szTmpBuf[4096] = {0};
	//	sprintf(szPathTmp,"%s\\Logs.txt",g_ExeDir);
	FILE *file=fopen("temp~1.s","w");
#ifdef __EA64__
	sprintf(szTmpBuf,"%s\n.byte 0x12,0x34,0x56,0x78,0x90,0x12,0x34,0x56,0xFF,0xFF,0xFF,0xFF",lpInData);
#else
	sprintf(szTmpBuf,"%s%d\n%s\n.byte 0x12,0x34,0x56,0x78,0x90,0x12,0x34,0x56,0xFF,0xFF,0xFF,0xFF",g_StaticData, 16 * (2 - g_nType), lpInData);
#endif
	fwrite(szTmpBuf,1,strlen(szTmpBuf),file);
	//	fwrite("\n",1,strlen("\n"),file);
	fseek(file,0,SEEK_SET);  
	fflush(file);               
	fclose(file); 
}
int Str_Find_str(const TCHAR *Srcstr, TCHAR *FindStr)
{
	int retIndex = -1;
	int len = strlen(FindStr);
	TCHAR *StrTmp = new TCHAR[len + 1];
	memset(StrTmp,0,len + 1);
	int SrcSize = strlen(Srcstr);
	for(int i = 0;i < SrcSize;i++)
	{
		memcpy(StrTmp,Srcstr + i,len);
		if(memcmp(StrTmp,FindStr,len) == 0)
		{
			retIndex = i;
		}
	}
	return retIndex;
}
int MyReadFile(char *lpFilePath, char **lpInBuf)
{
	FILE *lpF = fopen(lpFilePath, "rb");
	fseek(lpF, 0, SEEK_END);
	int nFileSize = ftell(lpF);
	fseek(lpF, 0, SEEK_SET);
	unsigned char* pvFile = (unsigned char*)malloc(nFileSize);
	fread(pvFile, 1, nFileSize, lpF);
	fclose(lpF);
	*lpInBuf = (char*)pvFile;
	return nFileSize;
}
#ifdef __EA64__
int ClacBL(DWORD dwSrc, DWORD dwDes, char *szOrdBuf, char *lpOutBuf)
{
#define  OFFSET_TO_ARM 0x50
	char szWriteFileBuf[512] = {0};
	char szTmpBuf[256] = {0};
	char szRetBuf[4096] = {0};
	char szCmdBuf[256] = {0};
	char *lpFileBuf = NULL;
	DWORD dwRange = 0;
	int dwRem = 0;
	if(dwSrc >= dwDes)
	{
		dwRange = dwSrc - dwDes;
		sprintf(szTmpBuf, "    .org 0x10\n\
						  asmgen:\n\
						  .org 0x%X\n\
						  %s asmgen\n\
						  nop\n\
						  nop", dwRange + 0x10, szOrdBuf);

	}
	else
	{
		dwRange = (dwDes - dwSrc) ;		

		sprintf(szTmpBuf, "    .org 0x10\n\
						  %s asmgen\n\
						  .org 0x%X\n\
						  asmgen: \n", szOrdBuf, dwRange + 0x10 );
	}
	strcat(szWriteFileBuf, szTmpBuf);
	/////////////////////////////////////////
	{
		FILE *file=fopen("temp~2.s","w");
		fwrite(szWriteFileBuf,1,strlen(szWriteFileBuf),file);
		//	fwrite("\n",1,strlen("\n"),file);
		fseek(file,0,SEEK_SET);  
		fflush(file);               
		fclose(file);
	}
	//	GetShortPathName(g_szReleasePath, szCmdBuf, sizeof(szCmdBuf));
	sprintf(szCmdBuf, "\"%s\" temp~2.s -o temp~2.o", g_szReleasePath);
	if( MyWinExec(szCmdBuf,szRetBuf,4096) <= (char*)1)
	{
		MessageBox(NULL, szCmdBuf, NULL, 0);
		return 0;
	}
	if(strstr(szRetBuf,"Error") > 0)
	{
		//strcpy(lpOutBuf,strstr(szRetBuf,"Error") + strlen("Error") + 1);
		strcpy(lpOutBuf,szRetBuf);
		return 0;
	}
	//////////////////////
	int nFileLen = MyReadFile("temp~2.o", &lpFileBuf);
	memset(szRetBuf, 0, sizeof(szRetBuf));
	int nOrdLen = 4;
	if(dwSrc >= dwDes)
	{
		memcpy(szRetBuf, lpFileBuf + OFFSET_TO_ARM + dwRange , nOrdLen);		//0x64 是跳过前面 废指令

	}
	else
	{
		memcpy(szRetBuf, lpFileBuf + OFFSET_TO_ARM , nOrdLen);
	}

	memcpy(lpOutBuf, szRetBuf, nOrdLen);
	free(lpFileBuf);
	DeleteFile("temp~2.s");
	DeleteFile("temp~2.o");
	return nOrdLen;
}
#else
int ClacBL(DWORD dwSrc, DWORD dwDes, char *szOrdBuf, char *lpOutBuf)
{
#define  OFFSET_TO_ARM 0x44
	char szTmpBuf[256] = {0};
	char szRetBuf[4096] = {0};
	char szCmdBuf[256] = {0};
	char *lpFileBuf = NULL;
	char szWriteFileBuf[2048] = ".globl _start\n\
								.align 2\n\
								_start:\n\
								.code 32\n";
	if(g_nType)
	{
		strcat(szWriteFileBuf, "\tadr r0, thumb + 1\n\
							   bx r0\n\
							   thumb:\n\
							   .code 16\n");
	}
	DWORD dwRange = 0;
	int dwRem = 0;
	if(dwSrc >= dwDes)
	{
		dwRange = (dwSrc - dwDes) / 0x10 * 0x10;
		dwRem = (dwSrc - dwDes) % 0x10 / 2;
		if(g_nType == 0)
		{
			dwRem /= 2;
		}
		sprintf(szTmpBuf, "    .org 0x10\n\
						  asmgen:\n\
						  .org 0x%X\n\
						  %s asmgen\n\
						  nop\n\
						  nop", dwRange + 0x10, szOrdBuf);

	}
	else
	{
		dwRange = (dwDes - dwSrc) / 0x10 * 0x10;
		dwRem = (dwDes - dwSrc) % 0x10 / 2 ;		
		if(g_nType == 0)
		{
			dwRem /= 2;
		}

		sprintf(szTmpBuf, "    .org 0x10\n\
						  %s asmgen\n\
						  nop\n\
						  nop\n\
						  .org 0x%X\n\
						  asmgen: \n", szOrdBuf, dwRange + 0x10 + 12);
	}
	strcat(szWriteFileBuf, szTmpBuf);
	/////////////////////////////////////////
	{
		FILE *file=fopen("temp~2.s","w");
		fwrite(szWriteFileBuf,1,strlen(szWriteFileBuf),file);
		//	fwrite("\n",1,strlen("\n"),file);
		fseek(file,0,SEEK_SET);  
		fflush(file);               
		fclose(file);
	}
//	GetShortPathName(g_szReleasePath, szCmdBuf, sizeof(szCmdBuf));
	sprintf(szCmdBuf, "\"%s\" temp~2.s -o temp~2.o", g_szReleasePath);
	if( MyWinExec(szCmdBuf,szRetBuf,4096) <= (char*)1)
	{
		MessageBox(NULL, szCmdBuf, NULL, 0);
		return 0;
	}
	if(strstr(szRetBuf,"Error") > 0)
	{
		//strcpy(lpOutBuf,strstr(szRetBuf,"Error") + strlen("Error") + 1);
		strcpy(lpOutBuf,szRetBuf);
		return 0;
	}
	//////////////////////
	int nFileLen = MyReadFile("temp~2.o", &lpFileBuf);
	memset(szRetBuf, 0, sizeof(szRetBuf));
	int nOrdLen = 4;
	if(dwSrc >= dwDes)
	{
		if( (g_nType == 1) && (*(DWORD*)(lpFileBuf + OFFSET_TO_ARM + dwRange  + 2) == 0x46C046C0) )
		{
			nOrdLen = 2;
		}

		memcpy(szRetBuf, lpFileBuf + OFFSET_TO_ARM + dwRange , nOrdLen);		//0x64 是跳过前面 废指令
		if(g_nType == 1)
		{
			szRetBuf[nOrdLen - 2] -= dwRem;
		}
		else
		{
			szRetBuf[0] -= dwRem;
		}
	}
	else
	{
		dwRem -= 3; //这里 减 3  是 3跳指令的长度
		if( (g_nType == 1) && (*(DWORD*)(lpFileBuf + OFFSET_TO_ARM + 2) == 0x46C046C0) )
		{
			nOrdLen = 2;
		}

		memcpy(szRetBuf, lpFileBuf + OFFSET_TO_ARM  , nOrdLen);
		if(g_nType == 1)
		{

			szRetBuf[nOrdLen - 2] += dwRem - 3;  //因为 thumb 指令是站2个字节 所以这个还要再跳过3个字节
		}
		else
		{
			DWORD dwTmp = 0;
			memcpy(&dwTmp, szRetBuf, 3);
			dwTmp += dwRem;
			memcpy(szRetBuf, &dwTmp, 3);
		}
	}

	memcpy(lpOutBuf, szRetBuf, nOrdLen);
	free(lpFileBuf);
	DeleteFile("temp~2.s");
	DeleteFile("temp~2.o");
	return nOrdLen;
}
#endif
void OnButtonCalc(HWND hwnd)
{
	if(SendMessage (FindWindowEx(hwnd, NULL, "Button", "ARM"), BM_GETCHECK, 0, 0))
	{
		g_nType = 0;
	}
	else
	{
		g_nType = 1;
	}
	char szTmpBuf[256] = {0};
	char *lpInData= NULL;
	TCHAR szCmdBuf[MAX_PATH]= {0};
	char *lpRetBuf= NULL;
	GetDlgItemText(hwnd, IDC_EDIT_ADDR, szTmpBuf, 256);
	int nInLen = SendDlgItemMessage(hwnd, IDC_EDIT_CODE, WM_GETTEXTLENGTH, NULL, (LPARAM)NULL);
	int nRetBufLen = 0;
	lpInData = (char*)malloc(nInLen  + 0x10);
	memset(lpInData, 0, nInLen + 0x10);
	if(nInLen > 4096)
	{
		nRetBufLen = nInLen  * 2;
		lpRetBuf = (char*)malloc(nRetBufLen);
	}
	else
	{
		nRetBufLen = 4096;
		lpRetBuf = (char*)malloc(nRetBufLen);
	}
	memset(lpRetBuf, 0, nRetBufLen);
	GetDlgItemText(hwnd, IDC_EDIT_CODE, lpInData, nInLen + 0x10);
	if(!lpInData[0])
	{
		MessageBox(NULL, "请输入汇编代码","Error", 0);
		free(lpInData);
		free(lpRetBuf);
		return;
	}
	if(!szTmpBuf[0])
	{
		MessageBox(NULL, "请输入地址","Error", 0);
		free(lpInData);
		free(lpRetBuf);
		return;
	}
	else if(szTmpBuf[0])
	{
		int i = 0;
		int nlen = strlen(szTmpBuf);
		for(i = 0; i < nlen; i++)
		{
			if(!isxdigit(szTmpBuf[i]))
			{
				MessageBox(NULL, "请输入有效地址","Error", 0);
				free(lpInData);
				free(lpRetBuf);
				return;
			}
		}
		
	}
#ifdef __EA64__
	g_Current = strtoul64(szTmpBuf, NULL, 16);
#else
	g_Current = strtoul(szTmpBuf, NULL, 16);
#endif
	if(!isLoaded(g_Current))
	{
		MessageBox(NULL, "请输入有效地址","Error", 0);
		free(lpInData);
		free(lpRetBuf);
		return;
	}
	BLArray blArrBuf[100] = {0};
	int nCount = 0;
	if(AnalyzerStr(lpInData, g_Current, lpRetBuf, blArrBuf,nCount) == 0)
	{
		MessageBox(NULL, "请输入内容","Error", 0);
		free(lpInData);
		free(lpRetBuf);
		return;
	}
	int i = 0;
	int j= 0;
	WriteSrcFile(lpRetBuf);
	memset(lpRetBuf, 0, nRetBufLen);
	sprintf(szCmdBuf, "%s temp~1.s -o temp~1.o", g_szReleasePath);
	MyWinExec(szCmdBuf,lpRetBuf, nRetBufLen);
	if(Str_Find_str(lpRetBuf,"Error") >= 0)
	{
		DeleteFile("temp~1.s");
		DeleteFile("temp~1.o");
		MessageBox(NULL, strstr(lpRetBuf, "Error"),"Error", 0);
		free(lpInData);
		free(lpRetBuf);
		return ;
	}
	memset(lpRetBuf,0, nRetBufLen);
	DWORD nCodeLen = 0;
	MapFile("temp~1.o",lpRetBuf, nCodeLen);
	for(i = 0; i < nCount; i++)
	{
		char szOrdBuf[256] = {0};
		int nARMB_len = ClacBL(blArrBuf[i].dwSrc, blArrBuf[i].dwDes, blArrBuf[i].lpRod, szOrdBuf);
		if(nARMB_len > 0)
		{
			memcpy(lpRetBuf + blArrBuf[i].nARMOffset, szOrdBuf, nARMB_len);
		}
		else
		{
			DeleteFile("temp~1.s");
			DeleteFile("temp~1.o");
			MessageBox(NULL, szOrdBuf, "Error ClacBL", 0);
			free(lpInData);
			free(lpRetBuf);
			return;
		}
	}
#ifdef __EA64__
	msg("========================\nPatch Addr: 0x%I64X Len: 0x%X\n原始数据:", g_Current, nCodeLen);
#else
	msg("========================\nPatch Addr: 0x%08X Len: 0x%X\n原始数据:", g_Current, nCodeLen);
#endif
	
	g_nCodeLen = nCodeLen;
	//TCHAR szTmpBuf[256] = {0};
	for( i = 0;i < (int)nCodeLen;i ++)
	{
		msg("%02X", get_byte(g_Current + i));
		patch_byte(g_Current + i, (byte)lpRetBuf[i]);
	}
	msg("\n补丁数据:");
	for( i = 0;i < (int)nCodeLen;i ++)
	{
		msg("%02X", (byte)lpRetBuf[i]);
	}
	msg("\n========================\n");
	//MessageBox(NULL,szTmpBuf, NULL, 0);
	refresh_idaview_anyway();
	DeleteFile("temp~1.s");
	DeleteFile("temp~1.o");
	free(lpInData);
	free(lpRetBuf);
	Main_OnClose(hwnd);
}
BOOL CALLBACK EnumWindowsProc(
	HWND hwnd,      // handle to parent window
	LPARAM lParam   // application-defined value
	)
{
	DWORD PID;
	BOOL  Result=TRUE;
	GetWindowThreadProcessId(hwnd,&PID);
	if (PID==GetCurrentProcessId())
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

ea_t strtoul64(const char *nptr, char **endptr, int base)
{
//	#   define ULLONG_MAX	18446744073709551615ULL
	const char *s;
	unsigned long long acc, cutoff;
	int c;
	int neg, any, cutlim;

	/*
	 * See strtoq for comments as to the logic used.
	 */
	s = nptr;
	do {
		c = (unsigned char) *s++;
	} while (isspace(c));
	if (c == '-') {
		neg = 1;
		c = *s++;
	} else { 
		neg = 0;
		if (c == '+')
			c = *s++;
	}
	if ((base == 0 || base == 16) &&
	    c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		base = 16;
	}
	if (base == 0)
		base = c == '0' ? 8 : 10;

	cutoff = ULLONG_MAX / (unsigned long long)base;
	cutlim = ULLONG_MAX % (unsigned long long)base;
	for (acc = 0, any = 0;; c = (unsigned char) *s++) {
		if (isdigit(c))
			c -= '0';
		else if (isalpha(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		else
			break;
		if (c >= base)
			break;
		if (any < 0)
			continue;
		if (acc > cutoff || (acc == cutoff && c > cutlim)) {
			any = -1;
			acc = ULLONG_MAX;
			errno = ERANGE;
		} else {
			any = 1;
			acc *= (unsigned long long)base;
			acc += c;
		}
	}
	if (neg && any > 0)
		acc = -acc;
	if (endptr != 0)
		*endptr = (char *) (any ? s - 1 : nptr);
	return (acc);
}
