#pragma once
#include <windows.h>
#include <string>


class ProcessToken {
public:
	ProcessToken(HANDLE processHandle, DWORD access);
	~ProcessToken();
	HANDLE getToken() const;
private:
	HANDLE m_token = nullptr;
};


class AddPrivilege {
public:
	AddPrivilege(std::string privilege);
	~AddPrivilege();
	bool isPrivileged() const;
private:
	std::string m_privilege;
	bool m_is_privileged;
};



bool enableDirectoryAccessAudit(const std::wstring directory);

bool disableDirectoryAccessAudit(const std::wstring directory);
