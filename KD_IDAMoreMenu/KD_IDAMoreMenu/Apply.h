#include <windows.h>
int SegWriteFile(unsigned char *lpMemAddr, unsigned char *lpInBuf, int nInBufLen, int nOffset);
BOOL IsFilterTable(char *lpName);
void  Apply_patches();
LRESULT CALLBACK ApplyDlgProc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);