#pragma once

#include <Windows.h>

#include "Monitor.h"



DWORD WINAPI MonitorEntryPoint(LPVOID param);

bool StartMonitorDirectory(const std::wstring & directory);
