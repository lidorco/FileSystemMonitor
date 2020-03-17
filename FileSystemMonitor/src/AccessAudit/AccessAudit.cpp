#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <iostream>

//#include "..\Log\Log.h"
#include "AccessAudit.h"


bool SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, bool bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (0 == LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
	{
		std::cout << "LookupPrivilegeValue failed " << GetLastError() << std::endl;
		return false;
	}

	// the number of entries in the Privileges array
	tp.PrivilegeCount = 1;
	// an array of LUID_AND_ATTRIBUTES structures
	tp.Privileges[0].Luid = luid;
	
	// If TRUE
	if (bEnablePrivilege) 
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		std::cout << "Privilege was enabled!";
	} 
	else 
	{
		tp.Privileges[0].Attributes = 0;
		std::cout << "Privilege was disabled!";
	}

	// Enable the privilege(or disable all privileges)
	if (!AdjustTokenPrivileges(
			hToken,
			FALSE,      // If TRUE, function disables all privileges,
						// if FALSE the function modifies privileges based on the tp
			&tp,
			sizeof(TOKEN_PRIVILEGES),
			(PTOKEN_PRIVILEGES)NULL,
			(PDWORD)NULL))
		{
			std::cout << "AdjustTokenPrivileges() failed, error: " << GetLastError() << std::endl;
			return false;
		}
	return true;
}


bool EnableDirectoryAccessAudit(const std::wstring directory)
{
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		std::cout << "OpenProcessToken  failed " << GetLastError() << std::endl;
		return false;
	}

	if (false == SetPrivilege(hToken, "SeSecurityPrivilege", TRUE)) 
	{
		return false;
	}

	SE_OBJECT_TYPE ObjectType = SE_FILE_OBJECT;
	PACL systemAcl = NULL;
	PSECURITY_DESCRIPTOR securityDescriptor = NULL;
	
	DWORD result = GetNamedSecurityInfoW(directory.c_str(), ObjectType, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, &systemAcl, &securityDescriptor);

	if (ERROR_SUCCESS != result) {
		//LOG("GetNamedSecurityInfoW failed");
		std::cout << "GetNamedSecurityInfoW  failed " << result << std::endl;
		return false;
	}
	std::cout << "GetNamedSecurityInfoW  worked " << result << std::endl;

	/*
	PSID everyoneSid = { 0 };
	if (0 == ConvertStringSidToSidA("S-1-1-0", &everyoneSid)) { //World :	S-1-1-0 		(A group that includes all users.)
		//LOG("ConvertStringSidToSidA failed");
		DWORD error = GetLastError();
		return false;
	}*/


	EXPLICIT_ACCESS ea;
	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	ea.grfAccessPermissions = GENERIC_ALL;
	ea.grfAccessMode = SET_AUDIT_SUCCESS;
	ea.grfInheritance = CONTAINER_INHERIT_ACE;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
	ea.Trustee.ptstrName = "Everyone";

	PACL updatedSystemAcl = NULL;
	result = SetEntriesInAcl(1, &ea, systemAcl, &updatedSystemAcl);
	if (result != ERROR_SUCCESS)
	{
		std::cout << "SetEntriesInAcl() failed, error " << result << std::endl;
		//Cleanup(pSS, pNewSACL);
		return false;
	}



	result = SetNamedSecurityInfoW(const_cast<LPWSTR>(directory.c_str()), SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, updatedSystemAcl);
	if (result != ERROR_SUCCESS)
	{
		std::cout << "SetNamedSecurityInfo() failed, error " << result << std::endl;
		//Cleanup(pSS, pNewSACL);
		return false;
	}

	/*
	if (0 == AddAuditAccessObjectAce(systemAcl, ACL_REVISION_DS, SUCCESSFUL_ACCESS_ACE_FLAG, GENERIC_ALL, NULL, NULL, everyoneSid, TRUE, FALSE)) {
		//LOG("AddAuditAccessObjectAce failed");
		DWORD error = GetLastError();
		return false;
	}*/

	return true;
}

bool DisableDirectoryAccessAudit(const std::wstring directory)
{
	return false;
}
