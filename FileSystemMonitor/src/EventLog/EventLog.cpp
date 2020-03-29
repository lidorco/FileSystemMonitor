#include <windows.h>
#include <conio.h>
#include <winevt.h>
#include <stdio.h>
#include <Sddl.h>
#include <string>
#include <iostream>

#include "../Monitor/Monitor.h"
#include "../libs/pugixml/pugixml.hpp"

#pragma comment(lib, "wevtapi.lib")

#define ARRAY_SIZE 10


void parseEventXml(const std::wstring& eventXml)
{
	pugi::xml_document doc;
	const pugi::xml_parse_result result = doc.load_string(eventXml.c_str());
	if (!result)
	{
		std::cout << "pugi xml failed loading event: " << result << std::endl;
		return;
	}

	std::wstring eventTime;
	auto pid = 0;
	std::wstring fileAccessed;
	std::wstring user;
	std::wstring process;
	std::wstring accessStr;

	const pugi::xml_node eventSystem = doc.child(L"Event").child(L"System");
	eventTime = eventSystem.child(L"TimeCreated").attribute(L"SystemTime").as_string();
	pid = eventSystem.child(L"Execution").attribute(L"ProcessID").as_int();

	pugi::xml_node eventData = doc.child(L"Event").child(L"EventData");
	for (pugi::xml_node data : eventData)
	{
		std::wstring dataName = data.attribute(L"Name").as_string();

		if (!dataName.compare(L"ObjectName")) {
			fileAccessed = data.child_value();
		}
		else if (!dataName.compare(L"SubjectUserName")) {
			user = data.child_value();
		}
		else if (!dataName.compare(L"ProcessName")) {
			process = data.child_value();
		}
		else if (!dataName.compare(L"AccessMask")) {
			accessStr = data.child_value();
		}
	}

	std::wcout << eventTime.c_str() << " " << pid << " " << process.c_str() << " " << user.c_str()
		<< " " << fileAccessed.c_str() << " " << accessStr.c_str() << std::endl;

}


// Render the event as an XML string and print it.
DWORD PrintEvent(EVT_HANDLE hEvent)
{
	DWORD status = ERROR_SUCCESS;
	DWORD dwBufferSize = 0;
	DWORD dwBufferUsed = 0;
	DWORD dwPropertyCount = 0;
	LPWSTR pRenderedContent = nullptr;
	std::wstring eventMessage;
	std::wstring trackedDir;

	if (!EvtRender(nullptr, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
	{
		if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
		{
			dwBufferSize = dwBufferUsed;
			pRenderedContent = (LPWSTR)malloc(dwBufferSize);
			if (pRenderedContent)
			{
				EvtRender(nullptr, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
			}
			else
			{
				wprintf(L"malloc failed\n");
				status = ERROR_OUTOFMEMORY;
				goto cleanup;
			}
		}

		if (ERROR_SUCCESS != (status = GetLastError()))
		{
			wprintf(L"EvtRender failed with %d\n", status);
			goto cleanup;
		}
	}

	eventMessage = std::wstring(pRenderedContent);
	trackedDir = getCurrentMonitor().getTrackedDirectory();
	if (eventMessage.find(trackedDir) != std::string::npos)
	{
		parseEventXml(pRenderedContent);
	}

cleanup:

	if (pRenderedContent) 
	{
		free(pRenderedContent);
	}

	return status;
}


// Enumerate the events in the result set.
DWORD enumerateResults(EVT_HANDLE hResults)
{
	DWORD status = ERROR_SUCCESS;
	EVT_HANDLE hEvents[ARRAY_SIZE];
	DWORD dwReturned = 0;

	while (true)
	{
		// Get a block of events from the result set.
		if (!EvtNext(hResults, ARRAY_SIZE, hEvents, INFINITE, 0, &dwReturned))
		{
			if (ERROR_NO_MORE_ITEMS != (status = GetLastError()))
			{
				wprintf(L"EvtNext failed with %lu\n", status);
			}

			goto cleanup;
		}

		// For each event, call the PrintEvent function which renders the
		// event for display.
		for (DWORD i = 0; i < dwReturned; i++)
		{
			if (ERROR_SUCCESS == (status = PrintEvent(hEvents[i])))
			{
				EvtClose(hEvents[i]);
				hEvents[i] = nullptr;
			}
			else
			{
				goto cleanup;
			}
		}
	}

cleanup:

	// Closes any events in case an error occurred above.
	for (DWORD i = 0; i < dwReturned; i++)
	{
		if (nullptr != hEvents[i])
			EvtClose(hEvents[i]);
	}

	return status;
}

// Determines whether the console input was a key event.
BOOL isKeyEvent(HANDLE hStdIn)
{
	INPUT_RECORD record[128];
	DWORD dwRecordsRead = 0;
	auto fKeyPress = FALSE;

	if (ReadConsoleInput(hStdIn, record, 128, &dwRecordsRead))
	{
		for (DWORD i = 0; i < dwRecordsRead; i++)
		{
			if (KEY_EVENT == record[i].EventType)
			{
				fKeyPress = TRUE;
				break;
			}
		}
	}

	return fKeyPress;
}

void pullerEventsSubscriber()
{
	DWORD status = ERROR_SUCCESS;
	EVT_HANDLE hSubscription = NULL;
	const LPWSTR pwsPath = L"Security";
	const LPWSTR pwsQuery = L"Event/System[EventID=4663]";
	HANDLE aWaitHandles[2];
	DWORD dwWait = 0;

	// Get a handle for console input, so you can break out of the loop.
	aWaitHandles[0] = GetStdHandle(STD_INPUT_HANDLE);
	if (INVALID_HANDLE_VALUE == aWaitHandles[0])
	{
		wprintf(L"GetStdHandle failed with %lu.\n", GetLastError());
		goto cleanup;
	}

	// Get a handle to a manual reset event object that the subscription will signal
	// when events become available that match your query criteria.
	aWaitHandles[1] = CreateEvent(nullptr, TRUE, TRUE, nullptr);
	if (nullptr == aWaitHandles[1])
	{
		wprintf(L"CreateEvent failed with %lu.\n", GetLastError());
		goto cleanup;
	}

	// Subscribe to events.
	hSubscription = EvtSubscribe(nullptr, aWaitHandles[1], pwsPath, pwsQuery, nullptr, nullptr, nullptr, EvtSubscribeStartAtOldestRecord);
	if (nullptr == hSubscription)
	{
		status = GetLastError();

		if (ERROR_EVT_CHANNEL_NOT_FOUND == status)
			wprintf(L"Channel %s was not found.\n", pwsPath);
		else if (ERROR_EVT_INVALID_QUERY == status)
			wprintf(L"The query %s was not found.\n", pwsQuery);
		else
			wprintf(L"EvtSubscribe failed with %lu.\n", status);

		goto cleanup;
	}

	wprintf(L"Press any key to quit.\n");

	// Loop until the user presses a key or there is an error.
	while (true)
	{
		dwWait = WaitForMultipleObjects(sizeof(aWaitHandles) / sizeof(HANDLE), aWaitHandles, FALSE, INFINITE);

		if (0 == dwWait - WAIT_OBJECT_0)  // Console input
		{
			if (isKeyEvent(aWaitHandles[0]))
				break;
		}
		else if (1 == dwWait - WAIT_OBJECT_0) // Query results
		{
			if (ERROR_NO_MORE_ITEMS != (status = enumerateResults(hSubscription)))
			{
				break;
			}

			ResetEvent(aWaitHandles[1]);
		}
		else
		{
			if (WAIT_FAILED == dwWait)
			{
				wprintf(L"WaitForSingleObject failed with %lu\n", GetLastError());
			}
			break;
		}
	}

cleanup:

	if (hSubscription)
		EvtClose(hSubscription);

	if (aWaitHandles[0])
		CloseHandle(aWaitHandles[0]);

	if (aWaitHandles[1])
		CloseHandle(aWaitHandles[1]);
}
