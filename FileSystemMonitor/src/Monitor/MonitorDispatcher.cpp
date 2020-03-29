#include <iostream>

#include "../EventLog/EventLog.h"
#include "../AccessAudit/AccessAudit.h"
#include "MonitorDispatcher.h"



DWORD WINAPI monitorEntryPoint(LPVOID param)
{
	auto monitor = reinterpret_cast<DirectoryMonitor*>(param);
	std::wcout << L"MonitorEntryPoint for " << monitor->getTrackedDirectory() << L" started!" << std::endl;
	
	enableDirectoryAccessAudit(monitor->getTrackedDirectory());
	pullerEventsSubscriber();
	disableDirectoryAccessAudit(monitor->getTrackedDirectory());
	
	std::wcout << L"MonitorEntryPoint for " << monitor->getTrackedDirectory() << L" ended!" << std::endl;

	return 0;
}


bool startMonitorDirectory(const std::wstring & directory)
{
	const auto monitor = new DirectoryMonitor(directory);
	DWORD threadId = 0;

	const auto thread = CreateThread(nullptr, 0, monitorEntryPoint, monitor, CREATE_SUSPENDED, &threadId);
	if (nullptr == thread) {
		std::cout << "Failed create thread! " << GetLastError() << std::endl;
		return false;
	}

	threadsToMonitor[threadId] = monitor;

	ResumeThread(thread);

	return true;
}



