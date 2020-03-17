#pragma once
#include <windows.h>
#include <string>


class ProcessToken {
public:
	ProcessToken(HANDLE processHandle, DWORD access);
	~ProcessToken();
	HANDLE getToken();
private:
	HANDLE m_token = NULL;
};

class AddPrivilege {
public:
	AddPrivilege(std::string privilege);
	~AddPrivilege();
	bool isPrivileged();
private:
	std::string m_privilege;
	bool m_is_privileged;
};



bool EnableDirectoryAccessAudit(const std::wstring directory);

bool DisableDirectoryAccessAudit(const std::wstring directory);
