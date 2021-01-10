#include "main.hpp"

LSA_HANDLE GetPolicyHandle()
{
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS ntsResult;
    LSA_HANDLE lsahPolicyHandle;

    // Object attributes are reserved, so initialize to zeros.
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
    ObjectAttributes.Length = sizeof(ObjectAttributes);

    // Get a handle to the Policy object.
    ntsResult = LsaOpenPolicy(
        NULL,    //Name of the target system.
        &ObjectAttributes, //Object attributes.
        POLICY_ALL_ACCESS | POLICY_LOOKUP_NAMES, //Desired access permissions.
        &lsahPolicyHandle  //Receives the policy handle.
    );

    if (ntsResult != STATUS_SUCCESS)
    {
        // An error occurred. Display it as a win32 error code.
        wprintf(L"OpenPolicy returned %lu\n", LsaNtStatusToWinError(ntsResult));
        return NULL;
    }
    return lsahPolicyHandle;
}

// Converts LPWSTR data to LSA_UNICODE_STRING structures
bool InitLsaString(PLSA_UNICODE_STRING pLsaString, LPCWSTR pwszString)
{
    DWORD dwLen = 0;

    if (NULL == pLsaString) return FALSE;

    if (NULL != pwszString)
    {
        dwLen = wcslen(pwszString);
        if (dwLen > 0x7ffe)   // String is too large
            return FALSE;
    }

    // Store the string.
    pLsaString->Buffer = (WCHAR*)pwszString;
    pLsaString->Length = (USHORT)dwLen * sizeof(WCHAR);
    pLsaString->MaximumLength = (USHORT)(dwLen + 1) * sizeof(WCHAR);

    return TRUE;
}

// Convert string to wstring
void convertStringToWString(std::wstring& ws, const std::string& s)
{
    std::wstring wsTmp(s.begin(), s.end());
    ws = wsTmp;
}
