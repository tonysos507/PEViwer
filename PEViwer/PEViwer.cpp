
#include "stdafx.h"
#include <Windows.h>
#include <winnt.h>
#include <clocale>
#include <cwchar>
#include <vector>
#include <iostream>

int main(int argc, char** argv)
{
	if (argc != 2)
		return -1;

	std::setlocale(LC_ALL, "en_US.utf8");
	std::mbstate_t state = std::mbstate_t();
	std::size_t len = 1 + std::mbsrtowcs(NULL, (const char**)&argv[1], 0, &state);
	std::vector<wchar_t> wstr(len);
	std::mbsrtowcs(&wstr[0], (const char**)&argv[1], wstr.size(), &state);

	HANDLE hFile = CreateFile(wstr.data(), GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return -1;

	DWORD dwFileSize = 0;
	dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize)
	{
		BYTE * pBuffer = NULL;
		pBuffer = new BYTE[dwFileSize + 2];
		if (pBuffer)
		{
			pBuffer[dwFileSize] = 0;
			pBuffer[dwFileSize + 1] = 0;
			DWORD dwRead = 0;
			ReadFile(hFile, pBuffer, dwFileSize, &dwRead, NULL);
			if (dwRead == dwFileSize)
			{
				PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pBuffer;
				if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
				{
					PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)(pBuffer + dosHeader->e_lfanew);
					if (pNTHeader->Signature == IMAGE_NT_SIGNATURE)
					{
						PIMAGE_SECTION_HEADER pNTSection;
						int nOffsetBuf = pNTHeader->OptionalHeader.BaseOfCode - pNTHeader->OptionalHeader.SizeOfHeaders;
						if (pNTHeader->OptionalHeader.Magic == 0x020b)
						{
							pNTSection = (PIMAGE_SECTION_HEADER)(pNTHeader + 1);
							if (pNTHeader->OptionalHeader.DataDirectory[0].Size)
							{
								std::cout << "export table: " << std::endl;
							}

							if (pNTHeader->OptionalHeader.DataDirectory[1].Size)
							{
								std::cout << "import table: " << std::endl;
								PIMAGE_SECTION_HEADER pNTSectionTmp = pNTSection;
								DWORD dwTemp = (DWORD)-1;
								DWORD dwMinus = nOffsetBuf;
								for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++)
								{
									if ((pNTHeader->OptionalHeader.DataDirectory[1].VirtualAddress >= pNTSectionTmp->VirtualAddress)
										&& (pNTHeader->OptionalHeader.DataDirectory[1].VirtualAddress + pNTHeader->OptionalHeader.DataDirectory[1].Size
											<= pNTSectionTmp->VirtualAddress + pNTSectionTmp->SizeOfRawData))
									{
										dwTemp = pNTSectionTmp->VirtualAddress - pNTSectionTmp->PointerToRawData;
										break;
									}
									pNTSectionTmp++;
								}
								if (dwTemp != -1)
									dwMinus = dwTemp;
								else
								{
									if (dwFileSize + pNTHeader->OptionalHeader.DataDirectory[1].Size < pNTHeader->OptionalHeader.DataDirectory[1].VirtualAddress)
									{
										printf("failed to create import table\n");
										return -1;
									}
								}

								TCHAR chFunction[1024];
								DWORD dwOffset = pNTHeader->OptionalHeader.DataDirectory[1].VirtualAddress;
								PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)&pBuffer[dwOffset - dwMinus];
								IMAGE_THUNK_DATA * pImageThunk = NULL;
								while ((pImport->OriginalFirstThunk) || (pImport->FirstThunk))
								{
									wsprintf(chFunction, _T("%S"), (TCHAR *)&pBuffer[pImport->Name - dwMinus]);
									std::wcout << L"Depend on " << chFunction << std::endl;
									IMAGE_IMPORT_DESCRIPTOR ImageDescriptor;
									memcpy(&ImageDescriptor, pImport, sizeof(IMAGE_IMPORT_DESCRIPTOR));
									if (pImport->OriginalFirstThunk)
										pImageThunk = (IMAGE_THUNK_DATA*)&pBuffer[pImport->OriginalFirstThunk - dwMinus];
									else
										pImageThunk = (IMAGE_THUNK_DATA*)&pBuffer[pImport->FirstThunk - dwMinus];
									while (pImageThunk->u1.Ordinal)
									{
										DWORD dwOffset = (0x7FFFFFFF & pImageThunk->u1.Function);
										int nOffset = dwOffset - dwMinus;
										if (nOffset > 0 && nOffset < dwFileSize)
										{
											short* pOridinal = (short*)&pBuffer[nOffset];
											int OrdinalNo = pOridinal[0];
											pOridinal++;
											if (!(0x80000000 & pImageThunk->u1.Function))
											{
												wsprintf(chFunction, _T("%S"), (TCHAR*)pOridinal);
												std::wcout << L"	ordinal " << OrdinalNo << L"	" << chFunction << std::endl;
											}
										}
										pImageThunk++;
									}

									pImport++;
								}
							}
						}
						else
							std::cout << "this is not x64 bit PE" << std::endl;
					}
				}
			}
		}
	}

	return 0;
}

