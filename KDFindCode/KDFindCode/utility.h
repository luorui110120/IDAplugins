
#ifndef _IDA_PLUGIN_TOOLS
#define  _IDA_PLUGIN_TOOLS
#include <windows.h>
#include <stdio.h>
#include <vector>
#include <string>
using namespace std;
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

unsigned int KMP(const char *Text,const char* Pattern,unsigned int startIndex);
void FilterSpacing(char *pbuf);
char*  GetCurrentDate(char *pOutbuf, int nOutSize);
unsigned int DichotomySearch(unsigned int *sSource, unsigned int array_size, unsigned int key,unsigned int startindex);
void* MALLOC(unsigned int nSize);
void FREE(void *p);
vector<string> tokenize(const string& src, string tok, bool trim=false, string null_subst="");
//²éÕÒ×Ö·û´®
int  FindingString(const char* lpszSour, const char* lpszFind, int nStart = 0);
//´øÍ¨Åä·ûµÄ×Ö·û´®Æ¥Åä
bool MatchingString(const char* lpszSour, const char* lpszMatch, bool bMatchCase = true);
//¶àÖØÆ¥Åä
bool MultiMatching(const char* lpszSour, const char* lpszMatch, int nMatchLogic = 0, bool bRetReversed = 0, bool bMatchCase = true);

char *trim(char *str);
#endif