// testProject.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


int main()
{
	
	EXPLICIT_ACCESS eDeny;
	DWORD dwAccessPermissions = GENERIC_WRITE | WRITE_DAC | DELETE | WRITE_OWNER | READ_CONTROL | PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD
		| PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA |
		PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | SYNCHRONIZE;

	//get process handle
	PACL pDacl = nullptr;

	BuildExplicitAccessWithName(&eDeny, TEXT("CURRENT_USER"), dwAccessPermissions, DENY_ACCESS, NO_INHERITANCE);
	std::cout << SetEntriesInAcl(1, &eDeny, nullptr, &pDacl);
	std::cout << std::endl << SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, pDacl, nullptr);
	std::cout << std::endl;
	LocalFree(pDacl);


	while(true)
	{
		
		Sleep(1000);
		std::cout << "Still running!" << std::endl;
	}
    return 0;
}

