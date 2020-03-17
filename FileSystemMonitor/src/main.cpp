//#include "Log\Log.h"
#include "EventLog\EventLog.h"
#include "AccessAudit\AccessAudit.h"

int main() {
	
	//LOG("File System Monitor started");
	
	EnableDirectoryAccessAudit(std::wstring(L"C:\\temp\\test\\test4"));

	//EventsSubscriber();
	
	return 0;
}

