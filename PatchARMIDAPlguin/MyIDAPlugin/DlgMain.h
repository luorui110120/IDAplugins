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


#pragma comment(lib,"ida.lib")
#define  USHORT ushort
#define  byte uchar
#define  UINT32 uint
typedef struct _BLArray
{
	DWORD dwSrc;
	DWORD dwDes;
	char lpRod[256];
	int nARMOffset;
}BLArray;
BOOL WINAPI Main_Proc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL Main_OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam);
void Main_OnCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify);
void Main_OnClose(HWND hwnd);
void OnButtonCalc(HWND hwnd);
BOOL Main_HotKey(HWND hwnd, int nId, WPARAM wParam, LPARAM lParam);
ea_t strtoul64(const char *nptr, char **endptr, int base);
BOOL CALLBACK EnumWindowsProc(
	HWND hwnd,      // handle to parent window
	LPARAM lParam   // application-defined value
	);
