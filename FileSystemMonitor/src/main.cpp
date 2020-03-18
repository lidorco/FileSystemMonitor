//#include "Log\Log.h"
//#include "EventLog\EventLog.h"
//#include "AccessAudit\AccessAudit.h"
#include "Monitor\MonitorDispatcher.h"


int main() {
	
	//LOG("File System Monitor started");
	

	StartMonitorDirectory(std::wstring(L"C:\\temp\\test\\test7"));
	
	/*
	EnableDirectoryAccessAudit(std::wstring(L"C:\\temp\\test\\test7"));
	EventsSubscriber();
	DisableDirectoryAccessAudit(std::wstring(L"C:\\temp\\test\\test7"));
	*/

	Sleep(10 * 60 * 1000);
	return 0;
}

