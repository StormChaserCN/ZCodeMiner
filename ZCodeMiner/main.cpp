#include <stdio.h>
#include <list>
#include <windows.h>

#define RET_OK 0
#define ARG_ERROR 0x100
#define PE_ERROR 0x200

typedef struct _CaveInfo 
{
	char SectionName[8];
	DWORD CaveSize, CaveHeader, CaveEnd, Offset;
}CaveInfo, *PCaveInfo;

void PrintUsage()
{
	printf("Usage: zcm [PEFILE].\n");
}

DWORD RVA2FOA(PIMAGE_NT_HEADERS pNT, DWORD dwRVA)
{
	DWORD dwOffset = 0, dwSecionSize = 0;
	WORD nSectionNum = pNT->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNT);
	if (pSectionHeader[0].PointerToRawData > dwRVA) //before first section
	{
		return dwOffset;
	}
	for (WORD i = 0; i < nSectionNum; ++i)
	{
		dwSecionSize = pSectionHeader[i].SizeOfRawData > pSectionHeader[i].Misc.VirtualSize ? pSectionHeader[i].SizeOfRawData : pSectionHeader[i].Misc.VirtualSize;
		if (dwRVA >= pSectionHeader[i].VirtualAddress &&
			dwRVA <= pSectionHeader[i].VirtualAddress + dwSecionSize)
		{
			dwOffset = pSectionHeader[i].PointerToRawData + dwRVA - pSectionHeader[i].VirtualAddress;
			break;
		}
	}
	return dwOffset;
}

DWORD AlignSize(DWORD nImgSize, DWORD nAlign)
{
	return ((nImgSize - 1) / nAlign + 1) * nAlign;
}

void PrintCave(CaveInfo cv)
{
	printf("SectionName:%s\n", cv.SectionName);
	printf("CaveStart:%x\n", cv.CaveHeader);
	printf("CaveSize:%d\n", cv.CaveSize);
}


int wmain(int argc, wchar_t *argv[], wchar_t *envp[])
{
	int nret = RET_OK;
	if (argc != 3)
	{
		PrintUsage();
		return ARG_ERROR;
	}

	int arg_size = _wtoi(argv[2]);
	printf("Checking PE format...\n");
	HANDLE hfile = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hfile == INVALID_HANDLE_VALUE)
	{
		return GetLastError();
	}
	DWORD dwReadRet = 0;
	DWORD dwFileSize = GetFileSize(hfile, NULL);
	PBYTE pMemImage = (PBYTE)VirtualAlloc(NULL, dwFileSize, MEM_COMMIT, PAGE_READWRITE);
	ReadFile(hfile, pMemImage, dwFileSize, &dwReadRet, NULL);
	CloseHandle(hfile);

	DWORD dwDosSize = sizeof(IMAGE_DOS_HEADER), dwNtSize = sizeof(IMAGE_NT_HEADERS);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pMemImage;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pMemImage + pDosHeader->e_lfanew);
	std::list<CaveInfo> caveList;
	if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		//valid dos header
		if (pNtHeaders->Signature == IMAGE_NT_SIGNATURE)
		{
			//valid pe header
			//basic info 
			WORD wSectionNum = pNtHeaders->FileHeader.NumberOfSections;
			DWORD dwImageSize = pNtHeaders->OptionalHeader.SizeOfImage;
			DWORD dwFileAlign = pNtHeaders->OptionalHeader.FileAlignment;
			DWORD dwSectionAlign = pNtHeaders->OptionalHeader.SectionAlignment;
			DWORD dwHeadersSize = pNtHeaders->OptionalHeader.SizeOfHeaders;
			PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
			
			for (int i = 0; i < wSectionNum; ++i)
			{
				//find blob
				BYTE blob = pMemImage[pSectionHeader->PointerToRawData+pSectionHeader->SizeOfRawData-1];

				//find cave
				int j;
				PBYTE p1, p2;
				BOOL bStatus = FALSE;
				for (j = 0, p1 = (pMemImage + pSectionHeader->PointerToRawData), p2 = p1; j < pSectionHeader->SizeOfRawData; ++j, p2++)
				{
					if (bStatus == FALSE)
					{
						if (*p2 == blob)
						{
							//find start of cave
							bStatus = TRUE;
							p1 = p2;
						}
					}
					else
					{
						//bStatus == TRUE --> enum cave size
						if(*p2 != blob)
						{
							if ((p2 - p1) >= arg_size)
							{
								CaveInfo cinfo;
								cinfo.CaveHeader = (DWORD)(p1-pMemImage);
								cinfo.CaveEnd = (DWORD)(p2-pMemImage);
								cinfo.CaveSize = p2 - p1;
								memcpy_s(cinfo.SectionName, 8, &(pSectionHeader->Name), 8);
								caveList.push_back(cinfo);
							}
							bStatus = FALSE;
						}
					}
				}
			}
			//print cave
			std::list<CaveInfo>::iterator it;
			for (it = caveList.begin(); it != caveList.end(); ++it)
			{
				PrintCave(*it);
			}
		}
		else
		{
			printf("Not valid PE file.\n");
			nret = PE_ERROR;
		}
	}
	else
	{
		printf("Not valid PE file.\n");
		nret = PE_ERROR;
	}
	VirtualFree(pMemImage, 0, MEM_RELEASE);
	return nret;
}