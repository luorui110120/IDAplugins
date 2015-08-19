/****************************************************************************
 * 360 crack elf header repair tool
 *                                         (c) 2014 martin of USTeam
 *****************************************************************************/
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "elf.h"
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <search.hpp>
#include <kernwin.hpp>


unsigned char ELF_MAGIC[] = {0x7f, 0x45, 0x4c, 0x46};

int repairelf_360(char *lpFilePath) 
{

    FILE *file = fopen(lpFilePath, "rb+");
    if (!file) {
        msg("input file not exists!\n");
        return -1;
    }
    fseek(file, 0L, SEEK_END);
    int size = ftell(file);

    Elf32_Ehdr header;

    //seek to begin && read
    fseek(file, 0L, SEEK_SET);
    fread(&header, 1, sizeof(Elf32_Ehdr), file);

	if (memcmp(&header, ELF_MAGIC, 4)) {
        msg("Invalid elf file[%s]!\n", lpFilePath);
        return 0;
	}

	if (header.e_type == ET_EXEC) {
        msg("ELF execute file[%s]\n", lpFilePath);
	} else if (header.e_type == ET_DYN) {
        msg("ELF shared file[%s]\n", lpFilePath);
	} else {
		msg("Unknown e_type : %d\n", header.e_type);
		msg("Aborting repair...\n");

		return -1;
	}

	if (header.e_phentsize == 32 && header.e_shentsize == 40 &&
            (header.e_shoff + header.e_shentsize * header.e_shnum) == size) {
        msg("The elf header is ok!\n");

        return 0;
	} else {
        msg("Invalid elf header, start repairing...\n");
	}

    //read all sections &&get string table index
    fseek(file, header.e_shoff, SEEK_SET);
    Elf32_Shdr sechd;
    int idx = 0;
    while (fread(&sechd, 1, sizeof(Elf32_Shdr), file)) {
        if (sechd.sh_type == SHT_STRTAB && sechd.sh_name == 1) {
            msg("find string table index:%d\n", idx);
            break;
        }

        idx++;
    }

	header.e_phentsize = 32;
	header.e_shentsize = 40;
	header.e_shnum = (size - header.e_shoff) / 40;
    header.e_shstrndx = idx;
    fseek(file, 0L, SEEK_SET);
    fwrite(&header, 1, sizeof(Elf32_Ehdr), file);
	fclose(file);
    msg("repair so OK!\n");
	return 0;
}
int repairelf(char *lpFilePath) 
{
	
	msg("=============================\n");
	if(INVALID_FILE_ATTRIBUTES == GetFileAttributes(lpFilePath))
	{
		msg("文件打开失败!\n");
		return -3;
	}
	else
	{
		char szBackPath[MAX_PATH] = {0};
		strcpy(szBackPath, lpFilePath);
		strcat(szBackPath, ".back");
		if(CopyFile(lpFilePath, szBackPath, TRUE))
		{
			msg("文件已备份: %s\n", szBackPath);
		}
	}
	HANDLE hFile=CreateFile(lpFilePath, GENERIC_WRITE | GENERIC_READ, 0, 
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);   //获得文件句柄
	HANDLE hMapping=CreateFileMapping(hFile,NULL,PAGE_READWRITE,0,0,NULL);  //创建内存映射对象
	if(INVALID_HANDLE_VALUE == hMapping)
	{
		msg("CreateFileMapping :%08X ErrorCode:%d\n", hMapping, GetLastError());
		return -1;
	}
	
	unsigned char* pvFile=(unsigned char*)MapViewOfFile(hMapping,FILE_MAP_ALL_ACCESS,0,0,0); //创建视图 就是映射文件到内存;
	int i = 0;
	int flag = 0;
#ifdef __EA64__
	Elf64_Dyn *t_dyn;
	Elf64_Phdr *t_phdr, *load1, *load2, *dynamic;
	Elf64_Ehdr* ehdr = (Elf64_Ehdr*) pvFile;
	t_phdr = (Elf64_Phdr*)(pvFile + sizeof(Elf64_Ehdr));
#else
	Elf32_Dyn *t_dyn;
	Elf32_Phdr *t_phdr, *load1, *load2, *dynamic;
	Elf32_Ehdr* ehdr = (Elf32_Ehdr*) pvFile;
	t_phdr = (Elf32_Phdr*)(pvFile + sizeof(Elf32_Ehdr));
#endif
	ea_t dwProgBase = 0, dwInitOffset, dwInitSize, dwFiniOffset, dwFiniSize;
	
	for(i=0;i<ehdr->e_phnum;i++)
	{
		if(t_phdr->p_type == PT_LOAD)
		{
			if(flag == 0)
			{
				load1 = t_phdr;
				flag = 1;
				//	printf("load1 = %p, offset = 0x%x \n", load1, load1->p_offset);
			}
			else
			{
				load2 = t_phdr;
				//		printf("load2 = %p, offset = 0x%x \n", load2, load2->p_offset);
			}
		}
		if(t_phdr->p_type == PT_DYNAMIC)
		{
			dynamic = t_phdr;
			msg("dynamic = %p, offset = 0x%x \n", dynamic, dynamic->p_offset);
			dwProgBase = dynamic->p_vaddr - dynamic->p_offset;
		}
		t_phdr ++;
	}
	//////////////////// 分析 dynamic 段中的 信息
#ifdef __EA64__
	t_dyn = (Elf64_Dyn*)(pvFile + dynamic->p_offset);
	for(i=0;i<dynamic->p_filesz / sizeof(Elf32_Dyn); i++)
	{
		switch (t_dyn->d_tag)
		{
		case DT_INIT_ARRAY:
			msg("INIT addr = 0x%llX\n", t_dyn->d_un.d_val );
			dwInitOffset = t_dyn->d_un.d_val - dwProgBase;
			break;
		case DT_INIT_ARRAYSZ:
			msg("INIT size = 0x%llX\n", t_dyn->d_un.d_val);
			dwInitSize = t_dyn->d_un.d_val ;
			break;
		case DT_FINI_ARRAY:
			msg("FINI addr = 0x%llX\n", t_dyn->d_un.d_val );
			dwFiniOffset = t_dyn->d_un.d_val - dwProgBase;
			break;
		case DT_FINI_ARRAYSZ:
			msg("FINI size = 0x%llX\n", t_dyn->d_un.d_val );
			dwFiniSize = t_dyn->d_un.d_val;
			break;
		}
		t_dyn ++;
	}
#else
	t_dyn = (Elf32_Dyn*)(pvFile + dynamic->p_offset);
	for(i=0;i<dynamic->p_filesz / sizeof(Elf32_Dyn); i++)
	{
		switch (t_dyn->d_tag)
		{
		case DT_INIT_ARRAY:
			msg("INIT addr = 0x%x\n", t_dyn->d_un.d_val );
			dwInitOffset = t_dyn->d_un.d_val - dwProgBase;
			break;
		case DT_INIT_ARRAYSZ:
			msg("INIT size = 0x%x\n", t_dyn->d_un.d_val);
			dwInitSize = t_dyn->d_un.d_val ;
			break;
		case DT_FINI_ARRAY:
			msg("FINI addr = 0x%x\n", t_dyn->d_un.d_val );
			dwFiniOffset = t_dyn->d_un.d_val - dwProgBase;
			break;
		case DT_FINI_ARRAYSZ:
			msg("FINI size = 0x%x\n", t_dyn->d_un.d_val );
			dwFiniSize = t_dyn->d_un.d_val;
			break;
		}
		t_dyn ++;
	}
#endif
#ifdef  __EA64__
	#define  ELF_ADDR_SIZE 8
#else
	#define  ELF_ADDR_SIZE 4
#endif
	for(i = 0; i < dwInitSize / ELF_ADDR_SIZE; i++)
	{
		ea_t addr = *(ea_t*)(pvFile + dwInitOffset + i * ELF_ADDR_SIZE);
		if(addr && (addr != -1 ) )
		{
	#ifdef  __EA64__
			msg("Init funtion rva: 0x%llX\n", addr);
	#else
			msg("Init funtion rva: 0x%08X\n", addr);
	#endif
		}
	}
	for(i = 0; i < dwFiniSize / ELF_ADDR_SIZE; i++)
	{
		ea_t addr = *(ea_t*)(pvFile + dwFiniOffset + i * ELF_ADDR_SIZE);
		if(addr && (addr != -1 ) )
		{
#ifdef  __EA64__
			msg("Fini funtion rva: 0x%llX\n", addr);
#else
			msg("Fini funtion rva: 0x%08X\n", addr);
#endif
		}
	}
	/////////将 section 设置为 0
	ehdr->e_shoff = 0;
	ehdr->e_shentsize = 0;
	ehdr->e_shnum = 0;
	ehdr->e_shstrndx = 0;
	////////////////
	CloseHandle(hMapping);
	//	msg("CloseHandle(hMapping)\n");
	if(0 == UnmapViewOfFile(pvFile) )
	{
		msg("文件修复失败! ErrorCode:%d\n", GetLastError());
		return -2;
	}
	else
	{
		msg("文件修复成功!\n");
		msg("=============================\n");
	}
	//	msg("UnmapViewOfFile(pvFile);\n");
	CloseHandle(hFile);
	return 0;
}