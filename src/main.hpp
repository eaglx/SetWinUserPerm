#pragma once
#include <windows.h>
#include <ntsecapi.h>
#include <ntstatus.h>
#include <wchar.h>
#include <cstdlib>
#include <sddl.h>
#include <iostream>
#include <string>

LSA_HANDLE GetPolicyHandle();
bool InitLsaString(PLSA_UNICODE_STRING, LPCWSTR);
void convertStringToWString(std::wstring&, const std::string&);
