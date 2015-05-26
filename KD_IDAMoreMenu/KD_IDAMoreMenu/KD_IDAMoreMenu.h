#define  MAXTOOLBARBTNNUM 10
#define  FUNCBTNNUM  MAXTOOLBARBTNNUM

HANDLE hBitmap[MAXTOOLBARBTNNUM];
HPEN	hPen;
BOOL    bDownFlag;
BOOL	bDrawFlag;
int	nDownNum;
HGDIOBJ  hToolBarColor[2];
HWND subhwnd;
DWORD  dwsumwight;

//////////////
BOOL	bDebugStat;				//是否在调试状态

UINT	g_uToolBarPos =0;	//保存鼠标按下时，处于当前按钮的位置

int		TOOLBARPOS = 0;//690;			//自画工具栏的开始位置
int		TOOLBARNUM=MAXTOOLBARBTNNUM;//自定义工具栏的实际个按钮总数
int		nCutomToolBarNum=0;	//实际工具栏数


////////////////函数申明
int DrawToolBar(HWND hWnd, int npos, HGDIOBJ hgdiobjtmp,HGDIOBJ a3, HGDIOBJ a4,int flag = 1);
int GetButtonPos(int x,int y);
void OpenProcDlg(UINT uid,DLGPROC proc);
void  ShowToolTip(HWND hwnd, char *lpBuf);