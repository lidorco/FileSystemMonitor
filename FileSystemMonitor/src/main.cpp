
#include "Monitor/MonitorDispatcher.h"


int main() {
	
	StartMonitorDirectory(std::wstring(L"C:\\temp\\test\\test7"));

	Sleep(10 * 60 * 1000);
	return 0;
}

