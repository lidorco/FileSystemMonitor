#include <aclapi.h>
#include <sddl.h>
#include <iostream>
#include <utility>

#include "AccessAudit.h"


bool setPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, bool bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (0 == LookupPrivilegeValue(nullptr, lpszPrivilege, &luid))
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
			static_cast<PTOKEN_PRIVILEGES>(nullptr),
			static_cast<PDWORD>(nullptr)))
		{
			std::cout << "AdjustTokenPrivileges() failed, error: " << GetLastError() << std::endl;
			return false;
		}
	return true;
}


ProcessToken::ProcessToken(HANDLE processHandle, DWORD access)
{
	if (!OpenProcessToken(processHandle, access, &m_token)) {
		m_token = nullptr;
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

HANDLE ProcessToken::getToken() const
{
	return m_token;
}

AddPrivilege::AddPrivilege(std::string privilege) : m_privilege(std::move(privilege)), m_is_privileged(false)
{
	const ProcessToken processToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES);
	if (!processToken.getToken())
	{
		return;
	}
	m_is_privileged = setPrivilege(processToken.getToken(), m_privilege.c_str(), TRUE);
}

AddPrivilege::~AddPrivilege()
{
	const ProcessToken processToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES);
	if (!processToken.getToken())
	{
		return;
	}
	m_is_privileged = setPrivilege(processToken.getToken(), m_privilege.c_str(), FALSE);
}

bool AddPrivilege::isPrivileged() const
{
	return m_is_privileged;
}



bool enableDirectoryAccessAudit(const std::wstring directory)
{
	const AddPrivilege privilege("SeSecurityPrivilege");
	if (!privilege.isPrivileged())
	{
		return false;
	}

	const SE_OBJECT_TYPE ObjectType = SE_FILE_OBJECT;
	PACL systemAcl = nullptr;
	PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
	
	DWORD result = GetNamedSecurityInfoW(directory.c_str(), ObjectType, SACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr,
		&systemAcl, &securityDescriptor);

	if (ERROR_SUCCESS != result) {
		std::cout << "GetNamedSecurityInfoW failed " << result << std::endl;
		return false;
	}
	std::cout << "GetNamedSecurityInfoW worked " << result << std::endl;


	EXPLICIT_ACCESS ea;
	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	ea.grfAccessPermissions = GENERIC_ALL;
	ea.grfAccessMode = SET_AUDIT_SUCCESS;
	ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
	ea.Trustee.ptstrName = "Everyone";

	PACL updatedSystemAcl = nullptr;
	result = SetEntriesInAcl(1, &ea, systemAcl, &updatedSystemAcl);
	if (result != ERROR_SUCCESS)
	{
		std::cout << "SetEntriesInAcl() failed, error " << result << std::endl;
		LocalFree(securityDescriptor);
		return false;
	}

	result = SetNamedSecurityInfoW(const_cast<LPWSTR>(directory.c_str()), SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, nullptr,
		nullptr, nullptr, updatedSystemAcl);
	if (result != ERROR_SUCCESS)
	{
		std::cout << "SetNamedSecurityInfo() failed, error " << result << std::endl;
		LocalFree(securityDescriptor);
		LocalFree(updatedSystemAcl);
		return false;
	}

	LocalFree(securityDescriptor);
	LocalFree(updatedSystemAcl);
	return true;
}

/*
Generate empty ACL for the directory
*/
bool disableDirectoryAccessAudit(const std::wstring directory)
{
	const AddPrivilege privilege("SeSecurityPrivilege");
	if (!privilege.isPrivileged())
	{
		return false;
	}

	PACL emptyAcl = nullptr;
	emptyAcl = static_cast<ACL*>(LocalAlloc(LPTR, sizeof(ACL)));
	if (0 == InitializeAcl(emptyAcl, sizeof(ACL), ACL_REVISION))
	{
		std::cout << "InitializeAcl() failed, error " << GetLastError() << std::endl;
		LocalFree(emptyAcl);
		return false;
	}

	const DWORD result = SetNamedSecurityInfoW(const_cast<LPWSTR>(directory.c_str()), SE_FILE_OBJECT, SACL_SECURITY_INFORMATION,
	                                           nullptr, nullptr, nullptr, emptyAcl);
	if (result != ERROR_SUCCESS)
	{
		std::cout << "SetNamedSecurityInfo() failed, error " << result << std::endl;
		LocalFree(emptyAcl);
		return false;
	}

	LocalFree(emptyAcl);
	return true;
}
