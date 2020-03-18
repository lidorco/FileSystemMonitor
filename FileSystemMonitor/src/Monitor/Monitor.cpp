#include <Windows.h>

#include "Monitor.h"



std::map<DWORD, DirectoryMonitor*> threadsToMonitor = std::map<DWORD, DirectoryMonitor*>();


DirectoryMonitor::DirectoryMonitor(const std::wstring & directory) : m_directory(std::wstring(directory))
{
}


std::wstring DirectoryMonitor::getTrackedDirectory()
{
	return m_directory;
}

DirectoryMonitor getCurrentMonitor()
{
	return *threadsToMonitor[GetCurrentThreadId()];
}
