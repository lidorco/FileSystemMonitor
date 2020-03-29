#pragma once
#include <string>
#include <map>



class DirectoryMonitor {

public:
	explicit DirectoryMonitor(const std::wstring& directory);	
	std::wstring getTrackedDirectory() const;

private:
	std::wstring m_directory;

};

extern std::map<DWORD, DirectoryMonitor*> threadsToMonitor;

DirectoryMonitor getCurrentMonitor();
