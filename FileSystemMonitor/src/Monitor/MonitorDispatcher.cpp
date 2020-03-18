#include <iostream>

#include "..\EventLog\EventLog.h"
#include "..\AccessAudit\AccessAudit.h"
#include "MonitorDispatcher.h"



DWORD WINAPI MonitorEntryPoint(LPVOID param)
{
	DirectoryMonitor* monitor = reinterpret_cast<DirectoryMonitor*>(param);
	std::wcout << L"MonitorEntryPoint for " << monitor->getTrackedDirectory() << L" started!" << std::endl;
	
	EnableDirectoryAccessAudit(monitor->getTrackedDirectory());
	EventsSubscriber();
	DisableDirectoryAccessAudit(monitor->getTrackedDirectory());
	
	std::wcout << L"MonitorEntryPoint for " << monitor->getTrackedDirectory() << L" ended!" << std::endl;

	return 0;
}


bool StartMonitorDirectory(const std::wstring & directory)
{
	DirectoryMonitor *monitor = new DirectoryMonitor(directory);
	DWORD threadId = 0;

	HANDLE thread = CreateThread(NULL, 0, MonitorEntryPoint, monitor, CREATE_SUSPENDED, &threadId);
	if (NULL == thread) {
		std::cout << "Failed create thread! " << GetLastError() << std::endl;
		return false;
	}

	threadsToMonitor[threadId] = monitor;

	ResumeThread(thread);

	return true;
}



