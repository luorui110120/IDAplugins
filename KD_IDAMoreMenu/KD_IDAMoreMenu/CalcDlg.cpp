//#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")  
//#pragma comment(lib,"comctl32.lib")  
#include "CalcDlg.h"
WNDPROC g_Edit;
WNDPROC g_LjEdit;
WNDPROC g_JZEdit;
WNDPROC g_JZEdit2;
HWND MainDlghwnd;
LRESULT CALLBACK CalcDlgProc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)  
{  
	switch (message)  
	{  
	case WM_INITDIALOG:  
		Dlg_Init(hwnd);
		break;  
	case WM_COMMAND:       
		{  
			switch (LOWORD(wParam))  
			{  
				//相加
				case IDC_SS_ADD_NUM1:
					Ssys_Add(hwnd);			//相加1
					break;
				case IDC_SS_ADD_NUM2:		//相加2
					Ssys_Add(hwnd);
					break;
				
					//相减
				case IDC_SS_SUB_NUM1:
					Ssys_Sub(hwnd);			
					break;
				case IDC_SS_SUB_NUM2:		
					Ssys_Sub(hwnd);
					break;
				
					//相乘
				case IDC_SS_MUL_NUM1:
					Ssys_Mul(hwnd);			
					break;
				case IDC_SS_MUL_NUM2:		
					Ssys_Mul(hwnd);
					break;
				
					//相除
				case IDC_SS_DIV_NUM1:
					Ssys_Div(hwnd);			
					break;
				case IDC_SS_DIV_NUM2:		
					Ssys_Div(hwnd);
					break;
					
					//取余
				case IDC_SS_MOD_NUM1:
					Ssys_Mod(hwnd);			
					break;
				case IDC_SS_MOD_NUM2:		
					Ssys_Mod(hwnd);
					break;
				//逻辑运算
				//XOR
				case IDC_LJ_XOR_NUM1:
					Ljys_XOR(hwnd);			
					break;
				case IDC_LJ_XOR_NUM2:		
					Ljys_XOR(hwnd);
					break;
					//AND
				case IDC_LJ_AND_NUM1:
					Ljys_AND(hwnd);			
					break;
				case IDC_LJ_AND_NUM2:		
					Ljys_AND(hwnd);
					break;
				
					//OR
				case IDC_LJ_OR_NUM1:
					Ljys_OR(hwnd);			
					break;
				case IDC_LJ_OR_NUM2:		
					Ljys_OR(hwnd);
					break;

					//NOT
				case IDC_LJ_NOT_NUM1:
					Ljys_NOT(hwnd);			
					break;
				//SHL
				case IDC_LJ_SHL_NUM1:
					Ljys_SHL(hwnd);			
					break;
				case IDC_LJ_SHL_NUM2:
					Ljys_SHL(hwnd);			
					break;

					//SHR
				case IDC_LJ_SHR_NUM1:
					Ljys_SHR(hwnd);			
					break;
				case IDC_LJ_SHR_NUM2:
					Ljys_SHR(hwnd);			
					break;
					//进制转换
				case IDC_EDT_TEXT:
					JZZH_TextZH(hwnd);
					break;
				case IDC_JZZH_DECTOHEX_DEC:
					JZZH_DecToHex(hwnd);
					break;
				case IDC_JZZH_HEXTODEC_HEX:
					JZZH_HexToDec(hwnd);
					break;
				//关闭
				case IDC_BTNCLOSE:			
					EndDialog(hwnd,IDOK); 
				break;  
			}  
			break;  

		}  

	case WM_CLOSE:  
		EndDialog(hwnd,IDOK);
		break;  
	}  
	return FALSE ;  
} 
//算术运算
LRESULT CALLBACK NewEditProc (HWND hwnd, UINT message, 
							  WPARAM wParam, LPARAM lParam)
{
	//TCHAR chCharCode;
	switch (message)
	{
	case WM_CHAR:
		wParam=toupper(wParam);
		if (!IsHex((TCHAR)wParam))
		{
			wParam=NULL;
		}
		break;
	}
	return CallWindowProc (g_Edit, hwnd, message, wParam, lParam);
}
//逻辑运算
LRESULT CALLBACK LJNewEditProc(HWND hwnd, UINT message, 
							   WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_CHAR:
		wParam=toupper(wParam);
		if (!LjIsHex((TCHAR)wParam))
		{
			wParam=NULL;
		}
		break;
	}
	return CallWindowProc (g_LjEdit, hwnd, message, wParam, lParam);

}
//进制转换
//判断是不是十六进制
LRESULT CALLBACK JZNewEditProc(HWND hwnd, UINT message, 
							   WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_CHAR:
		wParam=toupper(wParam);
		if (!JZIsHex((TCHAR)wParam))
		{
			wParam=NULL;
		}
		break;
	}
	return CallWindowProc (g_JZEdit, hwnd, message, wParam, lParam);
}
//判断是不是十进制
LRESULT CALLBACK JZNewEditProc2(HWND hwnd, UINT message, 
							   WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_CHAR:
		wParam=toupper(wParam);
		if (!JZIsDec((TCHAR)wParam))
		{
			wParam=NULL;
		}
		break;
	}
	return CallWindowProc (g_JZEdit2, hwnd, message, wParam, lParam);
}

//对话框初始化
void Dlg_Init(HWND hnwd)
{
	MainDlghwnd = hnwd;
	//算术运算
	/*g_Edit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_SS_ADD_NUM1), GWL_WNDPROC, (LONG)NewEditProc);
	g_Edit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_SS_ADD_NUM2), GWL_WNDPROC, (LONG)NewEditProc);

	g_Edit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_SS_SUB_NUM1), GWL_WNDPROC, (LONG)NewEditProc);
	g_Edit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_SS_SUB_NUM2), GWL_WNDPROC, (LONG)NewEditProc);

	g_Edit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_SS_MUL_NUM1), GWL_WNDPROC, (LONG)NewEditProc);
	g_Edit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_SS_MUL_NUM2), GWL_WNDPROC, (LONG)NewEditProc);

	g_Edit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_SS_DIV_NUM1), GWL_WNDPROC, (LONG)NewEditProc);
	g_Edit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_SS_DIV_NUM2), GWL_WNDPROC, (LONG)NewEditProc);

	g_Edit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_SS_MOD_NUM1), GWL_WNDPROC, (LONG)NewEditProc);
	g_Edit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_SS_MOD_NUM2), GWL_WNDPROC, (LONG)NewEditProc);*/
	CheckDlgButton(hnwd,IDC_SS_DEC,BST_CHECKED);	//算术运算，默认十进制
	//逻辑运算
	//g_LjEdit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_LJ_XOR_NUM1), GWL_WNDPROC, (LONG)LJNewEditProc);
	//g_LjEdit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_LJ_XOR_NUM2), GWL_WNDPROC, (LONG)LJNewEditProc);

	//g_LjEdit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_LJ_AND_NUM1), GWL_WNDPROC, (LONG)LJNewEditProc);
	//g_LjEdit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_LJ_AND_NUM2), GWL_WNDPROC, (LONG)LJNewEditProc);

	//g_LjEdit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_LJ_OR_NUM1), GWL_WNDPROC, (LONG)LJNewEditProc);
	//g_LjEdit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_LJ_OR_NUM2), GWL_WNDPROC, (LONG)LJNewEditProc);

	//g_LjEdit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_LJ_NOT_NUM1), GWL_WNDPROC, (LONG)LJNewEditProc);
	////g_LjEdit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_LJ_NOT_NUM2), GWL_WNDPROC, (LONG)LJNewEditProc);

	//g_LjEdit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_LJ_SHL_NUM1), GWL_WNDPROC, (LONG)LJNewEditProc);
	//g_LjEdit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_LJ_SHL_NUM2), GWL_WNDPROC, (LONG)LJNewEditProc);

	//g_LjEdit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_LJ_SHR_NUM1), GWL_WNDPROC, (LONG)LJNewEditProc);
	//g_LjEdit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_LJ_SHR_NUM2), GWL_WNDPROC, (LONG)LJNewEditProc);


	////进制转换
	//g_JZEdit = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_JZZH_DECTOHEX_DEC), GWL_WNDPROC, (LONG)JZNewEditProc2);
	//g_JZEdit2 = (WNDPROC)SetWindowLong(GetDlgItem(hnwd,IDC_JZZH_HEXTODEC_HEX), GWL_WNDPROC, (LONG)JZNewEditProc);

	CheckDlgButton(hnwd,IDC_LJ_DEC,BST_CHECKED);	//算术运算，默认十进制


	DWORD dwxlh;
	dwxlh = GetDirverInfo("c:\\");
	TCHAR szBuf[RETLEN] = {0};
	wsprintf(szBuf,"%ld",dwxlh);
	SetDlgItemText(hnwd,IDC_CDISK_SN,szBuf);
	wsprintf(szBuf,"%lx",dwxlh);
	HexCharUpper(szBuf);
	SetDlgItemText(hnwd,IDC_CDISK_SNHEX,szBuf);

	//SetDlgItemText(IDC_CDISK_SN,szbuf);

}

BOOL IsHex(TCHAR buf)
{
	if (buf == VK_BACK)  //如果是退格键，则直接返回
	{
		return TRUE;
	}
	//如果为十进制，则只能为 0 - 9 的数字
	if (IsDlgButtonChecked(MainDlghwnd,IDC_SS_DEC) == BST_CHECKED)
	{
		if ( buf>'9' || buf<'0')
		{
			return FALSE;
		}
	}
	else	//这是十六进制
	{
		if ( buf>'F' || buf<'0')
		{
			return FALSE;
		}
	}
	return TRUE;
}
BOOL LjIsHex(TCHAR buf)
{
	if (buf == VK_BACK)  //如果是退格键，则直接返回
	{
		return TRUE;
	}
	//如果为十进制，则只能为 0 - 9 的数字
	if (IsDlgButtonChecked(MainDlghwnd,IDC_LJ_DEC) == BST_CHECKED)
	{
		if ( buf>'9' || buf<'0')
		{
			return FALSE;
		}
	}
	else	//这是十六进制
	{
		if ( buf>'F' || buf<'0')
		{
			return FALSE;
		}
	}
	return TRUE;

}
//十六进制转换成十进制
unsigned long HexToDec(char *s) 
{ 
	int i,t; 
	unsigned long sum=0; 
	for(i=0;s[i];i++) 
	{ 
		if(s[i]<='9')
			t=s[i]-'0'; 
		else 
			t=s[i]-'A'+10; 
		sum=sum*16+t; 
	} 
	return sum; 
} 
//十六进制大写
void HexCharUpper(char *s)
{
	int i =0;
	for (i = 0;i<strlen(s);i++)
	{
		if (s[i]>='a')
		{
			s[i]=s[i]-32;
		}
	}
}

//算术运算  “+”
void Ssys_Add(HWND hwnd)
{
	TCHAR szBuf[RETLEN] = {0};
	if (IsDlgButtonChecked(hwnd,IDC_SS_DEC))
	{
		INT64 num1 = GetDlgItemInt(hwnd,IDC_SS_ADD_NUM1,NULL,TRUE);
		INT64 num2 = GetDlgItemInt(hwnd,IDC_SS_ADD_NUM2,NULL,TRUE);
		wsprintf(szBuf,"%ld",num1 + num2);
		SetDlgItemText(hwnd,IDC_SS_ADD_RET_DEC,szBuf);
		wsprintf(szBuf,"%lx",num1+num2);
		HexCharUpper(szBuf);
		SetDlgItemText(hwnd,IDC_SS_ADD_RET_HEX,szBuf);
		wsprintf(szBuf,"%u",num1+num2);
		SetDlgItemText(hwnd,IDC_SS_ADD_RET_UDEC,szBuf);
	}
	else
	{
		GetDlgItemText(hwnd,IDC_SS_ADD_NUM1,szBuf,RETLEN);
		HexCharUpper(szBuf);
		unsigned long num1 = HexToDec(szBuf);
		GetDlgItemText(hwnd,IDC_SS_ADD_NUM2,szBuf,RETLEN);
		HexCharUpper(szBuf);
		unsigned long num2 = HexToDec(szBuf);
		wsprintf(szBuf,"%ld",num1 + num2);
		SetDlgItemText(hwnd,IDC_SS_ADD_RET_DEC,szBuf);
		wsprintf(szBuf,"%lx",num1+num2);
		HexCharUpper(szBuf);
		SetDlgItemText(hwnd,IDC_SS_ADD_RET_HEX,szBuf);
		wsprintf(szBuf,"%u",num1+num2);
		SetDlgItemText(hwnd,IDC_SS_ADD_RET_UDEC,szBuf);
	}
}
//算术运算  “-”
void Ssys_Sub(HWND hwnd)
{
	TCHAR szBuf[RETLEN] = {0};
	if (IsDlgButtonChecked(hwnd,IDC_SS_DEC))
	{
		INT64 num1 = GetDlgItemInt(hwnd,IDC_SS_SUB_NUM1,NULL,TRUE);
		INT64 num2 = GetDlgItemInt(hwnd,IDC_SS_SUB_NUM2,NULL,TRUE);
		wsprintf(szBuf,"%ld",num1 - num2);
		SetDlgItemText(hwnd,IDC_SS_SUB_RET_DEC,szBuf);
		wsprintf(szBuf,"%lx",num1 - num2);
		HexCharUpper(szBuf);
		SetDlgItemText(hwnd,IDC_SS_SUB_RET_HEX,szBuf);
		wsprintf(szBuf,"%u",num1 - num2);
		SetDlgItemText(hwnd,IDC_SS_SUB_RET_UDEC,szBuf);
	}
	else
	{
		GetDlgItemText(hwnd,IDC_SS_SUB_NUM1,szBuf,RETLEN);
		HexCharUpper(szBuf);
		unsigned long num1 = HexToDec(szBuf);
		GetDlgItemText(hwnd,IDC_SS_SUB_NUM2,szBuf,RETLEN);
		HexCharUpper(szBuf);
		unsigned long num2 = HexToDec(szBuf);
		wsprintf(szBuf,"%ld",num1 - num2);
		SetDlgItemText(hwnd,IDC_SS_SUB_RET_DEC,szBuf);
		wsprintf(szBuf,"%lx",num1 - num2);
		HexCharUpper(szBuf);
		SetDlgItemText(hwnd,IDC_SS_SUB_RET_HEX,szBuf);
		wsprintf(szBuf,"%u",num1 - num2);
		SetDlgItemText(hwnd,IDC_SS_SUB_RET_UDEC,szBuf);
	}
}
//算术运算  “*”
void Ssys_Mul(HWND hwnd)
{
	TCHAR szBuf[RETLEN] = {0};
	if (IsDlgButtonChecked(hwnd,IDC_SS_DEC))
	{
		INT64 num1 = GetDlgItemInt(hwnd,IDC_SS_MUL_NUM1,NULL,TRUE);
		INT64 num2 = GetDlgItemInt(hwnd,IDC_SS_MUL_NUM2,NULL,TRUE);
		wsprintf(szBuf,"%ld",num1 * num2);
		SetDlgItemText(hwnd,IDC_SS_MUL_RET_DEC,szBuf);
		wsprintf(szBuf,"%lx",num1 * num2);
		HexCharUpper(szBuf);
		SetDlgItemText(hwnd,IDC_SS_MUL_RET_HEX,szBuf);
		wsprintf(szBuf,"%u",num1 * num2);
		SetDlgItemText(hwnd,IDC_SS_MUL_RET_UDEC,szBuf);
	}
	else
	{
		GetDlgItemText(hwnd,IDC_SS_MUL_NUM1,szBuf,RETLEN);
		HexCharUpper(szBuf);
		unsigned long num1 = HexToDec(szBuf);
		GetDlgItemText(hwnd,IDC_SS_MUL_NUM2,szBuf,RETLEN);
		HexCharUpper(szBuf);
		unsigned long num2 = HexToDec(szBuf);
		wsprintf(szBuf,"%ld",num1 * num2);
		SetDlgItemText(hwnd,IDC_SS_MUL_RET_DEC,szBuf);
		wsprintf(szBuf,"%lx",num1 * num2);
		HexCharUpper(szBuf);
		SetDlgItemText(hwnd,IDC_SS_MUL_RET_HEX,szBuf);
		wsprintf(szBuf,"%u",num1 * num2);
		SetDlgItemText(hwnd,IDC_SS_MUL_RET_UDEC,szBuf);
	}
}
//算术运算  “/”

void Ssys_Div(HWND hwnd)
{
	TCHAR szBuf[RETLEN] = {0};
	if (IsDlgButtonChecked(hwnd,IDC_SS_DEC))
	{
		INT64 num1 = GetDlgItemInt(hwnd,IDC_SS_DIV_NUM1,NULL,TRUE);
		INT64 num2 = GetDlgItemInt(hwnd,IDC_SS_DIV_NUM2,NULL,TRUE);
		if (num2>0)
		{
			wsprintf(szBuf,"%ld",num1 / num2);
			SetDlgItemText(hwnd,IDC_SS_DIV_RET_DEC,szBuf);
			wsprintf(szBuf,"%lx",num1 / num2);
			HexCharUpper(szBuf);
			SetDlgItemText(hwnd,IDC_SS_DIV_RET_HEX,szBuf);
			wsprintf(szBuf,"%u",num1 / num2);
			SetDlgItemText(hwnd,IDC_SS_DIV_RET_UDEC,szBuf);
		}
	}
	else
	{
		GetDlgItemText(hwnd,IDC_SS_DIV_NUM1,szBuf,RETLEN);
		HexCharUpper(szBuf);
		unsigned long num1 = HexToDec(szBuf);
		GetDlgItemText(hwnd,IDC_SS_DIV_NUM2,szBuf,RETLEN);
		HexCharUpper(szBuf);
		unsigned long num2 = HexToDec(szBuf);
		if (num2 >0)
		{
			wsprintf(szBuf,"%ld",num1 / num2);
			SetDlgItemText(hwnd,IDC_SS_DIV_RET_DEC,szBuf);
			wsprintf(szBuf,"%lx",num1 / num2);
			HexCharUpper(szBuf);
			SetDlgItemText(hwnd,IDC_SS_DIV_RET_HEX,szBuf);
			wsprintf(szBuf,"%u",num1 / num2);
			SetDlgItemText(hwnd,IDC_SS_DIV_RET_UDEC,szBuf);
		}
	}
}
//算术运算  “%”
void Ssys_Mod(HWND hwnd)
{
	TCHAR szBuf[RETLEN] = {0};
	if (IsDlgButtonChecked(hwnd,IDC_SS_DEC))
	{
		INT64 num1 = GetDlgItemInt(hwnd,IDC_SS_MOD_NUM1,NULL,TRUE);
		INT64 num2 = GetDlgItemInt(hwnd,IDC_SS_MOD_NUM2,NULL,TRUE);
		if (num2 >0)
		{
			wsprintf(szBuf,"%ld",num1 % num2);
			SetDlgItemText(hwnd,IDC_SS_MOD_RET_DEC,szBuf);
			wsprintf(szBuf,"%lx",num1 % num2);
			HexCharUpper(szBuf);
			SetDlgItemText(hwnd,IDC_SS_MOD_RET_HEX,szBuf);
			wsprintf(szBuf,"%u",num1 % num2);
			SetDlgItemText(hwnd,IDC_SS_MOD_RET_UDEC,szBuf);
		}
	}
	else
	{
		GetDlgItemText(hwnd,IDC_SS_MOD_NUM1,szBuf,RETLEN);
		HexCharUpper(szBuf);
		unsigned long num1 = HexToDec(szBuf);
		GetDlgItemText(hwnd,IDC_SS_MOD_NUM2,szBuf,RETLEN);
		HexCharUpper(szBuf);
		unsigned long num2 = HexToDec(szBuf);
		if (num2 >0)
		{
			wsprintf(szBuf,"%ld",num1 % num2);
			SetDlgItemText(hwnd,IDC_SS_MOD_RET_DEC,szBuf);
			wsprintf(szBuf,"%lx",num1 % num2);
			HexCharUpper(szBuf);
			SetDlgItemText(hwnd,IDC_SS_MOD_RET_HEX,szBuf);
			wsprintf(szBuf,"%u",num1 % num2);
			SetDlgItemText(hwnd,IDC_SS_MOD_RET_UDEC,szBuf);
		}
	}
}
//逻辑运算
//XOR
void Ljys_XOR(HWND hwnd)
{
	TCHAR szBuf[RETLEN] = {0};
	if (IsDlgButtonChecked(hwnd,IDC_LJ_DEC))
	{
		INT64 num1 = GetDlgItemInt(hwnd,IDC_LJ_XOR_NUM1,NULL,TRUE);
		INT64 num2 = GetDlgItemInt(hwnd,IDC_LJ_XOR_NUM2,NULL,TRUE);
		wsprintf(szBuf,"%ld",num1 ^ num2);
		SetDlgItemText(hwnd,IDC_LJ_XOR_RETDEC,szBuf);
		wsprintf(szBuf,"%lx",num1 ^ num2);
		HexCharUpper(szBuf);
		SetDlgItemText(hwnd,IDC_LJ_XOR_RETHEX,szBuf);
	}
	else
	{
		GetDlgItemText(hwnd,IDC_LJ_XOR_NUM1,szBuf,RETLEN);
		unsigned long num1 = HexToDec(szBuf);
		GetDlgItemText(hwnd,IDC_LJ_XOR_NUM2,szBuf,RETLEN);
		unsigned long num2 = HexToDec(szBuf);
		wsprintf(szBuf,"%ld",num1 ^ num2);
		SetDlgItemText(hwnd,IDC_LJ_XOR_RETDEC,szBuf);
		wsprintf(szBuf,"%lx",num1 ^ num2);
		HexCharUpper(szBuf);
		SetDlgItemText(hwnd,IDC_LJ_XOR_RETHEX,szBuf);

	}
}
//AND
void Ljys_AND(HWND hwnd)
{
	TCHAR szBuf[RETLEN] = {0};
	if (IsDlgButtonChecked(hwnd,IDC_LJ_DEC))
	{
		INT64 num1 = GetDlgItemInt(hwnd,IDC_LJ_AND_NUM1,NULL,TRUE);
		INT64 num2 = GetDlgItemInt(hwnd,IDC_LJ_AND_NUM2,NULL,TRUE);
		wsprintf(szBuf,"%ld",num1 & num2);
		SetDlgItemText(hwnd,IDC_LJ_AND_RETDEC,szBuf);
		wsprintf(szBuf,"%lx",num1 & num2);
		HexCharUpper(szBuf);
		SetDlgItemText(hwnd,IDC_LJ_AND_RETHEX,szBuf);
	}
	else
	{
		GetDlgItemText(hwnd,IDC_LJ_AND_NUM1,szBuf,RETLEN);
		HexCharUpper(szBuf);
		unsigned long num1 = HexToDec(szBuf);
		GetDlgItemText(hwnd,IDC_LJ_AND_NUM2,szBuf,RETLEN);
		HexCharUpper(szBuf);
		unsigned long num2 = HexToDec(szBuf);
		wsprintf(szBuf,"%ld",num1 & num2);
		SetDlgItemText(hwnd,IDC_LJ_AND_RETDEC,szBuf);
		wsprintf(szBuf,"%lx",num1 & num2);
		HexCharUpper(szBuf);
		SetDlgItemText(hwnd,IDC_LJ_AND_RETHEX,szBuf);

	}
}
//OR
void Ljys_OR(HWND hwnd)
{
	TCHAR szBuf[RETLEN] = {0};
	if (IsDlgButtonChecked(hwnd,IDC_LJ_DEC))
	{
		INT64 num1 = GetDlgItemInt(hwnd,IDC_LJ_OR_NUM1,NULL,TRUE);
		INT64 num2 = GetDlgItemInt(hwnd,IDC_LJ_OR_NUM2,NULL,TRUE);
		wsprintf(szBuf,"%ld",num1 | num2);
		SetDlgItemText(hwnd,IDC_LJ_OR_RETDEC,szBuf);
		wsprintf(szBuf,"%lx",num1 | num2);
		HexCharUpper(szBuf);
		SetDlgItemText(hwnd,IDC_LJ_OR_RETHEX,szBuf);
	}
	else
	{
		GetDlgItemText(hwnd,IDC_LJ_OR_NUM1,szBuf,RETLEN);
		unsigned long num1 = HexToDec(szBuf);
		GetDlgItemText(hwnd,IDC_LJ_OR_NUM2,szBuf,RETLEN);
		unsigned long num2 = HexToDec(szBuf);
		wsprintf(szBuf,"%ld",num1 | num2);
		SetDlgItemText(hwnd,IDC_LJ_OR_RETDEC,szBuf);
		wsprintf(szBuf,"%lx",num1 | num2);
		HexCharUpper(szBuf);
		SetDlgItemText(hwnd,IDC_LJ_OR_RETHEX,szBuf);
	}
}
//NOT
void Ljys_NOT(HWND hwnd)
{
	TCHAR szBuf[RETLEN] = {0};
	if (IsDlgButtonChecked(hwnd,IDC_LJ_DEC))
	{
		INT64 num1 = GetDlgItemInt(hwnd,IDC_LJ_NOT_NUM1,NULL,TRUE);

		//INT64 num2 = GetDlgItemInt(hwnd,IDC_LJ_OR_NUM2,NULL,TRUE);
		wsprintf(szBuf,"%ld", ~num1);
		SetDlgItemText(hwnd,IDC_LJ_NOT_RETDEC,szBuf);
		wsprintf(szBuf,"%lx",~num1);
		HexCharUpper(szBuf);
		SetDlgItemText(hwnd,IDC_LJ_NOT_RETHEX,szBuf);
	}
	else
	{
		GetDlgItemText(hwnd,IDC_LJ_NOT_NUM1,szBuf,RETLEN);
		HexCharUpper(szBuf);
		unsigned long num1 = HexToDec(szBuf);
		//GetDlgItemText(hwnd,IDC_LJ_OR_NUM2,szBuf,RETLEN);
		//unsigned long num2 = HexToDec(szBuf);
		wsprintf(szBuf,"%ld",~num1);
		SetDlgItemText(hwnd,IDC_LJ_NOT_RETDEC,szBuf);
		wsprintf(szBuf,"%lx",~num1);
		HexCharUpper(szBuf);
		SetDlgItemText(hwnd,IDC_LJ_NOT_RETHEX,szBuf);
	}

}
//SHL
void Ljys_SHL(HWND hwnd)
{
	TCHAR szBuf[RETLEN] = {0};
	if (IsDlgButtonChecked(hwnd,IDC_LJ_DEC))
	{
		INT64 num1 = GetDlgItemInt(hwnd,IDC_LJ_SHL_NUM1,NULL,TRUE);
		INT64 num2 = GetDlgItemInt(hwnd,IDC_LJ_SHL_NUM2,NULL,TRUE);
		wsprintf(szBuf,"%ld",num1 << num2);
		SetDlgItemText(hwnd,IDC_LJ_SHL_RETDEC,szBuf);
		wsprintf(szBuf,"%lx",num1 << num2);
		HexCharUpper(szBuf);
		SetDlgItemText(hwnd,IDC_LJ_SHL_RETHEX,szBuf);
	}
	else
	{
		GetDlgItemText(hwnd,IDC_LJ_SHL_NUM1,szBuf,RETLEN);
		HexCharUpper(szBuf);
		unsigned long num1 = HexToDec(szBuf);
		GetDlgItemText(hwnd,IDC_LJ_SHL_NUM2,szBuf,RETLEN);
		HexCharUpper(szBuf);
		unsigned long num2 = HexToDec(szBuf);
		wsprintf(szBuf,"%ld",num1 << num2);
		SetDlgItemText(hwnd,IDC_LJ_SHL_RETDEC,szBuf);
		wsprintf(szBuf,"%lx",num1 << num2);
		HexCharUpper(szBuf);
		SetDlgItemText(hwnd,IDC_LJ_SHL_RETHEX,szBuf);
	}

}
//SHR
void Ljys_SHR(HWND hwnd)
{
	TCHAR szBuf[RETLEN] = {0};
	if (IsDlgButtonChecked(hwnd,IDC_LJ_DEC))
	{
		INT64 num1 = GetDlgItemInt(hwnd,IDC_LJ_SHR_NUM1,NULL,TRUE);
		INT64 num2 = GetDlgItemInt(hwnd,IDC_LJ_SHR_NUM2,NULL,TRUE);
		wsprintf(szBuf,"%ld",num1 >> num2);
		SetDlgItemText(hwnd,IDC_LJ_OR_RETDEC,szBuf);
		wsprintf(szBuf,"%lx",num1 >> num2);
		HexCharUpper(szBuf);
		SetDlgItemText(hwnd,IDC_LJ_OR_RETHEX,szBuf);
	}
	else
	{
		GetDlgItemText(hwnd,IDC_LJ_SHR_NUM1,szBuf,RETLEN);
		HexCharUpper(szBuf);
		unsigned long num1 = HexToDec(szBuf);
		GetDlgItemText(hwnd,IDC_LJ_SHR_NUM2,szBuf,RETLEN);
		HexCharUpper(szBuf);
		unsigned long num2 = HexToDec(szBuf);
		wsprintf(szBuf,"%ld",num1 >> num2);
		SetDlgItemText(hwnd,IDC_LJ_SHR_RETDEC,szBuf);
		wsprintf(szBuf,"%lx",num1 >> num2);
		HexCharUpper(szBuf);
		SetDlgItemText(hwnd,IDC_LJ_SHR_RETHEX,szBuf);
	}

}

void JZZH_TextZH(HWND hwnd)
{
	TCHAR szBuf[RETLEN] = {0};
	TCHAR szRetBuf[MAX_BUF] = {0};
	TCHAR szTemp[5] ={0}; 
	int nRet = 0;
	GetDlgItemText(hwnd,IDC_EDT_TEXT,szBuf,RETLEN);
	for (int i =0;i<strlen(szBuf);i++)
	{
		wsprintf(szTemp,"%x,",szBuf[i]);
		strcat(szRetBuf+strlen(szRetBuf),szTemp);
		nRet += szBuf[i];
	}
	SetDlgItemText(hwnd,IDC_TEXT_ASCII,szRetBuf);
	wsprintf(szBuf,"%ld",nRet);
	SetDlgItemText(hwnd,IDC_TEXT_SUMDEC,szBuf);
	wsprintf(szBuf,"%lx",nRet);
	HexCharUpper(szBuf);
	SetDlgItemText(hwnd,IDC_TEXT_SUMHEX,szBuf);
}
BOOL JZIsDec(TCHAR buf)
{
	if (buf == VK_BACK)  //如果是退格键，则直接返回
	{
		return TRUE;
	}
	//如果为十进制，则只能为 0 - 9 的数字
	if ( buf>'9' || buf<'0')
	{
		return FALSE;
	}
	return TRUE;
}
BOOL JZIsHex(TCHAR buf)
{
	if (buf == VK_BACK)  //如果是退格键，则直接返回
	{
		return TRUE;
	}
	//如果为十进制，则只能为 0 - 9 的数字
	if ( buf>'F' || buf<'0')
	{
		return FALSE;
	}
	return TRUE;
}
void JZZH_DecToHex(HWND hwnd)
{
	TCHAR szBuf[RETLEN] = {0};
	INT64 num1 = GetDlgItemInt(hwnd,IDC_JZZH_DECTOHEX_DEC,NULL,TRUE);
	//SetDlgItemText(hwnd,IDC_TEXT_ASCII,szRetBuf);
	//wsprintf(szBuf,"%ld",nRet);
	//SetDlgItemText(hwnd,IDC_TEXT_SUMDEC,szBuf);
	wsprintf(szBuf,"%lx",num1);
	HexCharUpper(szBuf);
	SetDlgItemText(hwnd,IDC_JZZH_DECTOHEX_HEX,szBuf);
}
void JZZH_HexToDec(HWND hwnd)
{
	TCHAR szBuf[RETLEN] = {0};
	GetDlgItemText(hwnd,IDC_JZZH_HEXTODEC_HEX,szBuf,RETLEN);
	HexCharUpper(szBuf);
	unsigned long num1 = HexToDec(szBuf);
	//INT64 num1 = GetDlgItemInt(hwnd,IDC_JZZH_HEXTODEC_HEX,NULL,TRUE);
	//SetDlgItemText(hwnd,IDC_TEXT_ASCII,szRetBuf);
	wsprintf(szBuf,"%ld",num1);
	SetDlgItemText(hwnd,IDC_JZZH_HEXTODEC_DEC,szBuf);
}
DWORD GetDirverInfo(LPSTR szDrive)
{
	//UINT uDriveType;
	DWORD dwVolumeSerialNumber;
	DWORD dwMaximumComponentLength;
	DWORD dwFileSystemFlags;
	TCHAR szFileSystemNameBuffer[BUFSIZE];
	if (!GetVolumeInformation(
		szDrive, NULL, 0,
		&dwVolumeSerialNumber,
		&dwMaximumComponentLength,
		&dwFileSystemFlags,
		szFileSystemNameBuffer,
		BUFSIZE
		))
	{
		return -1;
	}
	return dwVolumeSerialNumber;
}
