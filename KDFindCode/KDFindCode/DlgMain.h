#include <windows.h>
#include <windowsx.h>
#include "resource.h"
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>
#include <srarea.hpp>
#include <name.hpp>
#include <search.hpp>
#include "utility.h"


//#define  IDA_DEBUG

#ifdef IDA_DEBUG
#define LOGD(fmt, ...)  msg(fmt, __VA_ARGS__)
#else
#define LOGD(fmt, ...)
#endif

#pragma comment(lib,"ida.lib")
#define  USHORT ushort
#define  byte uchar
#define  UINT32 uint

#define NETNODE_BUFFER_MAX   0x400
#define NETNODE_START_INDEX  1000

#define WM_CREATE_SHAPSHOOT (WM_USER + 101)

typedef struct _strbufindex
{
	unsigned int dwbufoffset;
	unsigned int dwasmaddr;
}strbufindex;
typedef struct _strbuftable
{
	unsigned int dwBufArrayCount;	// n_asmbuf 有多少个数组
	unsigned int dwOffsetArrayCount;
	unsigned int dwAddrArrayCount;
	char szDate[256];
}strbuftable;

BOOL WINAPI Main_Proc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL Main_OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam);
void Main_OnCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify);
void Main_OnClose(HWND hwnd);
void OnButtonFind(HWND hwnd);
BOOL Main_HotKey(HWND hwnd, int nId, WPARAM wParam, LPARAM lParam);
void Main_OnCreateSnapshootPlan(HWND hwnd, WPARAM wParam, LPARAM lParam);
int  ShowState(HWND hwnd, const char *format,... );
int SelectRadio(HWND hwnd, int nIDDlgItem);
BOOL CALLBACK EnumWindowsProc(
	HWND hwnd,      // handle to parent window
	LPARAM lParam   // application-defined value
	);