#pragma once

#include <Windows.h>

#include "Monitor.h"



DWORD WINAPI monitorEntryPoint(LPVOID param);

bool startMonitorDirectory(const std::wstring & directory);
