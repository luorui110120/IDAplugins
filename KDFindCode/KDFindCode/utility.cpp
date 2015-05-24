#include "utility.h"
void get_nextval(const char *T, int next[])
{
	// 求模式串T的next函数值并存入数组 next。
	int j = 0, k = -1;
	next[0] = -1;
	while ( T[j/*+1*/] != '\0' )
	{
		if (k == -1 || T[j] == T[k])
		{
			++j; ++k;
			if (T[j]!=T[k])
				next[j] = k;
			else
				next[j] = next[k];
		}// if
		else
			k = next[k];
	}// while
	////这里是我加的显示部分
	// for(int  i=0;i<j;i++)
	//{
	//     cout<<next[i];
	//}
	//cout<<endl;
}// get_nextval　
unsigned int KMP(const char *Text,const char* Pattern, unsigned int startIndex) //const 表示函数内部不会改变这个参数的值。
{
	if( !Text||!Pattern||  Pattern[0]=='\0'  ||  Text[0]=='\0' )//
		return -1;//空指针或空串，返回-1。
	unsigned int len=0;
	const char * c=Pattern;
	while(*c++!='\0')//移动指针比移动下标快。
	{    
		++len;//字符串长度。
	}
	int *next=new int[len+1];
	get_nextval(Pattern,next);//求Pattern的next函数值

	unsigned int index=startIndex,i=0,j=0;
	while(Text[i]!='\0'  && Pattern[j]!='\0' )
	{
		if(Text[i]== Pattern[j])
		{
			++i;// 继续比较后继字符
			++j;
		}
		else
		{
			index += j-next[j];
			if(next[j]!=-1)
				j=next[j];// 模式串向右移动
			else
			{
				j=0;
				++i;
			}
		}
	}//while

	delete []next;
	if(Pattern[j]=='\0')
		return index + startIndex;// 匹配成功
	else
		return -1;      
}
void FilterSpacing(char *pbuf)
{
	int i = 0, j = 0;
	int len = 0;
	if(pbuf == NULL || 0 == strlen(pbuf))
	{
		return ;
	}
	len = strlen(pbuf);
	for(i = 0; i < len; i++)
	{
		if(pbuf[i] == ' ' || pbuf[i] == '\t' )
		{
			if(j && pbuf[j - 1] != ' ')
			{
				pbuf[j] = ' ';
				j++;
			}
			continue;
		}
		else
		{
			pbuf[j] = pbuf[i];
			j++;
		}
	}
	pbuf[j] = 0;
}
char*  GetCurrentDate(char *pOutbuf, int nOutSize)
{
	if(pOutbuf && nOutSize)
	{
		SYSTEMTIME stLocal;  
		::GetLocalTime(&stLocal);  
		//显示时间的间隔。  
		_snprintf(pOutbuf,nOutSize,"%u/%u/%u %u:%u:%u",                   
			stLocal.wYear, stLocal.wMonth, stLocal.wDay,  
			stLocal.wHour, stLocal.wMinute, stLocal.wSecond);  
	}
	return pOutbuf;
}
/* 二分查找
 * 算法思想：1、将数组排序(从小到大)；2、每次跟中间的数mid比较，如果相等可以直接返回，
 * 如果比mid大则继续查找大的一边，否则继续查找小的一边。

  输入：排序好的数组 - sSource[]，数组大小 - array_size，查找的值 - key
  返回：找到返回相应的位置，否则返回-1
*/
unsigned int DichotomySearch(unsigned int *sSource, unsigned int array_size, unsigned int key, unsigned int startindex)
{	
	unsigned int low = 0, high = array_size - 1, mid;
	low= startindex;
	while (low <= high)
	{		
		mid = (low + high) / 2;//获取中间的位置
		
		if (sSource[mid] == key)			
			return mid ;	//找到则返回相应的位置
		if (sSource[mid] > key)			
			high = mid - 1;	//如果比key大，则往低的位置查找
		else
			low = mid + 1;	//如果比key小，则往高的位置查找
	}	
	return -1;	
}
void* MALLOC(unsigned int nSize)
{
	void *pret = malloc(nSize);
	if(pret)
	{
		memset(pret, 0, nSize);
	}
	return pret;
}
void FREE(void *p)
{
	if(p)
	{
		free(p);
	}
}
vector<string> tokenize(const string& src, string tok,            
	bool trim, string null_subst)  
{  
	if( src.empty() || tok.empty() ) 
		throw "tokenize: empty string\0";  

	vector<string> v;  
	int pre_index = 0, index = 0, len = 0;  
	while ((index = src.find_first_of(tok, pre_index)) > 0) 
	{  
		if( (len = index-pre_index) > 0 )  
		{
			string s = src.substr(pre_index, len);
			s.erase(0,s.find_first_not_of(" "));	//删除 首尾空格
			s.erase(s.find_last_not_of(" ") + 1); 
			v.push_back(s);  
		}
		else if(trim)  
			v.push_back(null_subst);  
		pre_index = index+1;  
	}  
	string endstr = src.substr(pre_index); 
	endstr.erase(0,endstr.find_first_not_of(" "));  
	endstr.erase(endstr.find_last_not_of(" ") + 1); 
	if( trim) v.push_back( endstr.empty()?null_subst:endstr );  
	else if( !endstr.empty() ) 
		v.push_back(endstr);  
	return v;  
}
//功  能：在lpszSour中查找字符串lpszFind，lpszFind中可以包含通配字符‘?’
//参  数：nStart为在lpszSour中的起始查找位置
//返回值：成功返回匹配位置，否则返回-1
//注  意：Called by “bool MatchingString()”
int FindingString(const char* lpszSour, const char* lpszFind, int nStart /* = 0 */)
{
	//	ASSERT(lpszSour && lpszFind && nStart >= 0);
	if(lpszSour == NULL || lpszFind == NULL || nStart < 0)
		return -1;

	int m = strlen(lpszSour);
	int n = strlen(lpszFind);

	if( nStart+n > m )
		return -1;

	if(n == 0)
		return nStart;

	//KMP算法
	int* next = new int[n];
	//得到查找字符串的next数组
	{	n--;

	int j, k;
	j = 0;
	k = -1;
	next[0] = -1;

	while(j < n)
	{	if(k == -1 || lpszFind[k] == '?' || lpszFind[j] == lpszFind[k])
	{	j++;
	k++;
	next[j] = k;
	}
	else
		k = next[k];
	}

	n++;
	}

	int i = nStart, j = 0;
	while(i < m && j < n)
	{
		if(j == -1 || lpszFind[j] == '?' || lpszSour[i] == lpszFind[j])
		{	i++;
		j++;
		}
		else
			j = next[j];
	}

	delete []next;

	if(j >= n)
		return i-n;
	else
		return -1;
}

//功	  能：带通配符的字符串匹配
//参	  数：lpszSour是一个普通字符串；
//			  lpszMatch是一可以包含通配符的字符串；
//			  bMatchCase为0，不区分大小写，否则区分大小写。
//返  回  值：匹配，返回1；否则返回0。
//通配符意义：
//		‘*’	代表任意字符串，包括空字符串；
//		‘?’	代表任意一个字符，不能为空；
//时	  间：	2001.11.02	13:00
bool MatchingString(const char* lpszSour, const char* lpszMatch, bool bMatchCase /*  = true */)
{
	//	ASSERT(AfxIsValidString(lpszSour) && AfxIsValidString(lpszMatch));
	if(lpszSour == NULL || lpszMatch == NULL)
		return false;

	if(lpszMatch[0] == 0)//Is a empty string
	{
		if(lpszSour[0] == 0)
			return true;
		else
			return false;
	}

	int i = 0, j = 0;

	//生成比较用临时源字符串'szSource'
	char* szSource =
		new char[ (j = strlen(lpszSour)+1) ];

	if( bMatchCase )
	{	//memcpy(szSource, lpszSour, j);
		while( *(szSource+i) = *(lpszSour+i++) );
	}
	else
	{	//Lowercase 'lpszSour' to 'szSource'
		i = 0;
		while(lpszSour[i])
		{	if(lpszSour[i] >= 'A' && lpszSour[i] <= 'Z')
		szSource[i] = lpszSour[i] - 'A' + 'a';
		else
			szSource[i] = lpszSour[i];

		i++;
		}
		szSource[i] = 0;
	}

	//生成比较用临时匹配字符串'szMatcher'
	char* szMatcher = new char[strlen(lpszMatch)+1];

	//把lpszMatch里面连续的“*”并成一个“*”后复制到szMatcher中
	i = j = 0;
	while(lpszMatch[i])
	{
		szMatcher[j++] = (!bMatchCase) ?
			( (lpszMatch[i] >= 'A' && lpszMatch[i] <= 'Z') ?//Lowercase lpszMatch[i] to szMatcher[j]
			lpszMatch[i] - 'A' + 'a' :
		lpszMatch[i]
		) :
		lpszMatch[i];		 //Copy lpszMatch[i] to szMatcher[j]
		//Merge '*'
		if(lpszMatch[i] == '*')
			while(lpszMatch[++i] == '*');
		else
			i++;
	}
	szMatcher[j] = 0;

	//开始进行匹配检查

	int nMatchOffset, nSourOffset;

	bool bIsMatched = true;
	nMatchOffset = nSourOffset = 0;
	while(szMatcher[nMatchOffset])
	{
		if(szMatcher[nMatchOffset] == '*')
		{
			if(szMatcher[nMatchOffset+1] == 0)
			{	//szMatcher[nMatchOffset]是最后一个字符

				bIsMatched = true;
				break;
			}
			else
			{	//szMatcher[nMatchOffset+1]只能是'?'或普通字符

				int nSubOffset = nMatchOffset+1;

				while(szMatcher[nSubOffset])
				{	if(szMatcher[nSubOffset] == '*')
				break;
				nSubOffset++;
				}

				if( strlen(szSource+nSourOffset) <
					size_t(nSubOffset-nMatchOffset-1) )
				{	//源字符串剩下的长度小于匹配串剩下要求长度
					bIsMatched = false; //判定不匹配
					break;			//退出
				}

				if(!szMatcher[nSubOffset])//nSubOffset is point to ender of 'szMatcher'
				{	//检查剩下部分字符是否一一匹配

					nSubOffset--;
					int nTempSourOffset = strlen(szSource)-1;
					//从后向前进行匹配
					while(szMatcher[nSubOffset] != '*')
					{
						if(szMatcher[nSubOffset] == '?')
							;
						else
						{	if(szMatcher[nSubOffset] != szSource[nTempSourOffset])
						{	bIsMatched = false;
						break;
						}
						}
						nSubOffset--;
						nTempSourOffset--;
					}
					break;
				}
				else//szMatcher[nSubOffset] == '*'
				{	nSubOffset -= nMatchOffset;

				char* szTempFinder = new char[nSubOffset];
				nSubOffset--;
				memcpy(szTempFinder, szMatcher+nMatchOffset+1, nSubOffset);
				szTempFinder[nSubOffset] = 0;

				int nPos = ::FindingString(szSource+nSourOffset, szTempFinder, 0);
				delete []szTempFinder;

				if(nPos != -1)//在'szSource+nSourOffset'中找到szTempFinder
				{	nMatchOffset += nSubOffset;
				nSourOffset += (nPos+nSubOffset-1);
				}
				else
				{	bIsMatched = false;
				break;
				}
				}
			}
		}		//end of "if(szMatcher[nMatchOffset] == '*')"
		else if(szMatcher[nMatchOffset] == '?')
		{
			if(!szSource[nSourOffset])
			{	bIsMatched = false;
			break;
			}
			if(!szMatcher[nMatchOffset+1] && szSource[nSourOffset+1])
			{	//如果szMatcher[nMatchOffset]是最后一个字符，
				//且szSource[nSourOffset]不是最后一个字符
				bIsMatched = false;
				break;
			}
			nMatchOffset++;
			nSourOffset++;
		}
		else//szMatcher[nMatchOffset]为常规字符
		{
			if(szSource[nSourOffset] != szMatcher[nMatchOffset])
			{	bIsMatched = false;
			break;
			}
			if(!szMatcher[nMatchOffset+1] && szSource[nSourOffset+1])
			{	bIsMatched = false;
			break;
			}
			nMatchOffset++;
			nSourOffset++;
		}
	}

	delete []szSource;
	delete []szMatcher;
	return bIsMatched;
}

//功  能：多重匹配，不同匹配字符串之间用‘,’隔开
//			如：“*.h,*.cpp”将依次匹配“*.h”和“*.cpp”
//参  数：nMatchLogic = 0, 不同匹配求或，else求与；bMatchCase, 是否大小敏感
//返回值：如果bRetReversed = 0, 匹配返回true；否则不匹配返回true
//时  间：2001.11.02  17:00
bool MultiMatching(const char* lpszSour, const char* lpszMatch, int nMatchLogic /* = 0 */, bool bRetReversed /* = 0 */, bool bMatchCase /* = true */)
{
	//	ASSERT(AfxIsValidString(lpszSour) && AfxIsValidString(lpszMatch));
	if(lpszSour == NULL || lpszMatch == NULL)
		return false;

	char* szSubMatch = new char[strlen(lpszMatch)+1];
	bool bIsMatch;

	if(nMatchLogic == 0)//求或
	{	bIsMatch = 0;
	int i = 0;
	int j = 0;
	while(1)
	{	if(lpszMatch[i] != 0 && lpszMatch[i] != ',')
	szSubMatch[j++] = lpszMatch[i];
	else
	{	szSubMatch[j] = 0;
	if(j != 0)
	{
		bIsMatch = MatchingString(lpszSour, szSubMatch, bMatchCase);
		if(bIsMatch)
			break;
	}
	j = 0;
	}

	if(lpszMatch[i] == 0)
		break;
	i++;
	}
	}
	else//求与
	{	bIsMatch = 1;
	int i = 0;
	int j = 0;
	while(1)
	{	if(lpszMatch[i] != 0 && lpszMatch[i] != ',')
	szSubMatch[j++] = lpszMatch[i];
	else
	{	szSubMatch[j] = 0;

	bIsMatch = MatchingString(lpszSour, szSubMatch, bMatchCase);
	if(!bIsMatch)
		break;

	j = 0;
	}

	if(lpszMatch[i] == 0)
		break;
	i++;
	}
	}

	delete []szSubMatch;

	if(bRetReversed)
		return !bIsMatch;
	else
		return bIsMatch;
}
char *trim(char *str)
{
	int i = 0;
	int j = 0;
	int len = strlen(str);

	if(str !=NULL && len>0)
	{
		for (i = 0; i<len; i++)
		{
			if (*(str+i) != ' ' && *(str+i) != '\t')
			{
				break;
			}
		}
		for (j = len-1; j>=0; j--)
		{
			if (*(str+j) !=' ' && *(str+j) != '\t')
			{
				break;
			}
		}
		*(str+j+1) = '\0';
	}
	return str+i;//等价于return memmove(str,str+i,j-i+2);此处其实亦可以用memcpy（参考其实现）
}