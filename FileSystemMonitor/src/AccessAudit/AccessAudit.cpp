#include <aclapi.h>
#include <sddl.h>
#include <iostream>

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
	
	if (bEnablePrivilege) 
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		std::cout << "Privilege was enabled!" << std::endl;
	} 
	else 
	{
		tp.Privileges[0].Attributes = 0;
		std::cout << "Privilege was disabled!" << std::endl;
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


ProcessToken::ProcessToken(HANDLE processHandle, DWORD access)
{
	if (!OpenProcessToken(processHandle, access, &m_token)) {
		m_token = NULL;
		std::cout << "OpenProcessToken failed " << GetLastError() << std::endl;
	}
	else {
		std::cout << "OpenProcessToken succeed " << GetLastError() << std::endl;
	}
}

ProcessToken::~ProcessToken()
{
	if (m_token) {
		CloseHandle(m_token);
	}
}

HANDLE ProcessToken::getToken()
{
	return m_token;
}

AddPrivilege::AddPrivilege(std::string privilege) : m_privilege(privilege), m_is_privileged(false)
{
	ProcessToken processToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES);
	if (!processToken.getToken())
	{
		return;
	}
	m_is_privileged = SetPrivilege(processToken.getToken(), m_privilege.c_str(), TRUE);
}

AddPrivilege::~AddPrivilege()
{
	ProcessToken processToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES);
	if (!processToken.getToken())
	{
		return;
	}
	m_is_privileged = SetPrivilege(processToken.getToken(), m_privilege.c_str(), FALSE);
}

bool AddPrivilege::isPrivileged()
{
	return m_is_privileged;
}



bool EnableDirectoryAccessAudit(const std::wstring directory)
{
	AddPrivilege privilege("SeSecurityPrivilege");
	if (!privilege.isPrivileged())
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

	return true;
}

/*
Generate empty ACL for the directory
*/
bool DisableDirectoryAccessAudit(const std::wstring directory)
{
	AddPrivilege privilege("SeSecurityPrivilege");
	if (!privilege.isPrivileged())
	{
		return false;
	}


	PACL emptyAcl = NULL;
	emptyAcl = (ACL*)LocalAlloc(LPTR, sizeof(ACL));
	if (0 == InitializeAcl(emptyAcl, sizeof(ACL), ACL_REVISION))
	{
		std::cout << "InitializeAcl() failed, error " << GetLastError() << std::endl;
	}

	DWORD result = SetNamedSecurityInfoW(const_cast<LPWSTR>(directory.c_str()), SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, emptyAcl);
	if (result != ERROR_SUCCESS)
	{
		std::cout << "SetNamedSecurityInfo() failed, error " << result << std::endl;
		//Cleanup(pSS, pNewSACL);
		return false;
	}

	return false;
}
