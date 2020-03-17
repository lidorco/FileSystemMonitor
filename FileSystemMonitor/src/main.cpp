//#include "Log\Log.h"
#include "EventLog\EventLog.h"
#include "AccessAudit\AccessAudit.h"

int main() {
	
	//LOG("File System Monitor started");
	
	EnableDirectoryAccessAudit(std::wstring(L"C:\\temp\\test\\test7"));
	EventsSubscriber();
	DisableDirectoryAccessAudit(std::wstring(L"C:\\temp\\test\\test7"));
	
	return 0;
}

