#pragma once
#include <iostream>
#include <string>
#include <map>



class DirectoryMonitor {

public:
	DirectoryMonitor(const std::wstring& directory);	
	std::wstring getTrackedDirectory();

private:
	std::wstring m_directory;

};

extern std::map<DWORD, DirectoryMonitor*> threadsToMonitor;

DirectoryMonitor getCurrentMonitor();
