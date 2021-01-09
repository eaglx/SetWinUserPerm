#include "main.hpp"

int GetSIDInformation(LPWSTR AccountName, LSA_HANDLE &PolicyHandle, PSID &AccountSID)
{
    AccountSID = NULL;
    LSA_UNICODE_STRING lucName;
    PLSA_TRANSLATED_SID ltsTranslatedSID;
    PLSA_REFERENCED_DOMAIN_LIST lrdlDomainList;
    LSA_TRUST_INFORMATION myDomain;
    NTSTATUS ntsResult;
    PWCHAR DomainString = NULL;

    // Initialize an LSA_UNICODE_STRING with the name.
    if (!InitLsaString(&lucName, AccountName))
    {
        wprintf(L"Failed InitLsaString\n");
        return -1;
    }

    ntsResult = LsaLookupNames(
        PolicyHandle,     // handle to a Policy object
        1,                // number of names to look up
        &lucName,         // pointer to an array of names
        &lrdlDomainList,  // receives domain information
        &ltsTranslatedSID // receives relative SIDs
    );
    if (STATUS_SUCCESS != ntsResult)
    {
        wprintf(L"Failed LsaLookupNames - %lu \n", LsaNtStatusToWinError(ntsResult));
        return -1;
    }

    // Get the domain the account resides in.
    myDomain = lrdlDomainList->Domains[ltsTranslatedSID->DomainIndex];
    DomainString = (PWCHAR)LocalAlloc(LPTR, myDomain.Name.Length + 1);
    if (DomainString == NULL) {
        wprintf(L"Failed LocalAlloc");
        LocalFree(DomainString);
        LsaFreeMemory(ltsTranslatedSID);
        LsaFreeMemory(lrdlDomainList);
        return -1;
    }

    wcsncpy_s(DomainString, myDomain.Name.Length + 1,myDomain.Name.Buffer, myDomain.Name.Length);
    LPWSTR sidDomainStr;
    if(!ConvertSidToStringSidW(myDomain.Sid, &sidDomainStr)) wprintf(L"Failed ConvertSidToStringSidA!\n");
    // Display the relative Id. 
    //wprintf(L"Relative Id is %lu %ws in domain %ws.\n", ltsTranslatedSID->RelativeId, sidDomainStr, DomainString);

    std::wstring sidString = sidDomainStr;
    sidString.push_back(L'-');
    sidString += std::to_wstring(ltsTranslatedSID->RelativeId);

    if (!ConvertStringSidToSidW(sidString.c_str(), &AccountSID)) wprintf(L"Failed ConvertSidToStringSidW!\n");

    LocalFree(DomainString);
    LsaFreeMemory(ltsTranslatedSID);
    LsaFreeMemory(lrdlDomainList);
    return 0;
}

int AddPrivileges(PSID AccountSID, LSA_HANDLE PolicyHandle, LPCWSTR newPermission)
{
    LSA_UNICODE_STRING lucPrivilege;
    NTSTATUS ntsResult;

    // Create an LSA_UNICODE_STRING for the privilege names.
    if (!InitLsaString(&lucPrivilege, newPermission)) //L"SeServiceLogonRight")) <- example to add a user as log as a servcie 
    {
        wprintf(L"Failed InitLsaString\n");
        return -1;
    }

    ntsResult = LsaAddAccountRights(
        PolicyHandle,  // An open policy handle.
        AccountSID,    // The target SID.
        &lucPrivilege, // The privileges.
        1              // Number of privileges.
    );
    if (ntsResult == STATUS_SUCCESS)
    {
        wprintf(L"Privilege added.\n");
        return 0;
    }
    else
    {
        wprintf(L"Privilege was not added - %lu \n", LsaNtStatusToWinError(ntsResult));
        return -1;
    }
}

int main(int argc, char* argv[])
{
    //char accountNameChar[] = "user name";
    wchar_t accountNameWCharT[20];
    size_t outSize;
    //mbstowcs_s(&outSize, accountNameWCharT, 20, accountNameChar, strlen(accountNameChar) + 1);
    mbstowcs_s(&outSize, accountNameWCharT, 20, argv[1], strlen(argv[1]) + 1);
    std::wstring newUserPermission;
    convertStringToWString(newUserPermission, std::string(argv[2]));
    LPWSTR accountNameLPWSTR = accountNameWCharT;

    LSA_HANDLE lsahPolicyHandle = GetPolicyHandle();
    if(lsahPolicyHandle == NULL) return -1;
    PSID AccountSID;

    if (GetSIDInformation(accountNameLPWSTR, lsahPolicyHandle, AccountSID) != 0) return -1;
    if(AccountSID == NULL) return -1;
    return AddPrivileges(AccountSID, lsahPolicyHandle, newUserPermission.c_str());
}
