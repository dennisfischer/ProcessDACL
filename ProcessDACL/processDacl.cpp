#include "targetver.h"

#include <stdio.h>
#include <iostream>
#include <tchar.h>

#include "Windows.h"
#include "aclapi.h"
#include "accctrl.h"
#pragma comment(lib, "advapi32.lib")

#include <SDKDDKVer.h>

int main()
{
	//The permissions that should be remaining. 
	//Virtual memory access is no longer possible as PROCESS_VM_WRITE,
	//PROCESS_VM_READ and PROCESS_VM_OPERATION are missing.
	DWORD dwAccessPermissions = GENERIC_WRITE | WRITE_DAC | DELETE |
		WRITE_OWNER | READ_CONTROL |
		PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD |
		PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION |
		PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA |
		PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | SYNCHRONIZE;

	//Now build the DACL object with the Windows API functions
	PACL pDacl = nullptr;
	EXPLICIT_ACCESS eDeny;
	BuildExplicitAccessWithName(&eDeny, TEXT("CURRENT_USER"), dwAccessPermissions, DENY_ACCESS, NO_INHERITANCE);
	SetEntriesInAcl(1, &eDeny, nullptr, &pDacl);

	//Now set the DACL to this process
	SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, pDacl, nullptr);

	//Cleanup object
	LocalFree(pDacl);

	//Further code
	//...
	return 0;
}

