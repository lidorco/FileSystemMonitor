
#include "Monitor/MonitorDispatcher.h"


int main() {
	
	startMonitorDirectory(std::wstring(L"C:\\temp\\test\\test7"));

	Sleep(10 * 60 * 1000);
	return 0;
}

