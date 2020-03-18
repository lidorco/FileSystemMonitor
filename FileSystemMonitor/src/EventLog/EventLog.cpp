#include <windows.h>
#include <conio.h>
#include <winevt.h>
#include <stdio.h>
#include <Sddl.h>
#include <string>
#include <iostream>

#include "..\Monitor\Monitor.h"
#include "..\libs\pugixml\pugixml.hpp"

#pragma comment(lib, "wevtapi.lib")


void ParseEventXml(const std::wstring& eventXml)
{
	pugi::xml_document doc;
	pugi::xml_parse_result result = doc.load_string(eventXml.c_str());
	if (!result)
	{
		std::cout << "pugi xml failed loading event: " << result << std::endl;
		return;
	}

	std::wstring eventTime;
	int pid = 0;
	std::wstring fileAccessed;
	std::wstring user;
	std::wstring process;
	std::wstring accessStr;
	DWORD access;

	pugi::xml_node eventSystem = doc.child(L"Event").child(L"System");
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
	LPWSTR pRenderedContent = NULL;
	std::wstring msg, trackedDir;

	if (!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
	{
		if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
		{
			dwBufferSize = dwBufferUsed;
			pRenderedContent = (LPWSTR)malloc(dwBufferSize);
			if (pRenderedContent)
			{
				EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
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

	msg = std::wstring(pRenderedContent);
	trackedDir = getCurrentMonitor().getTrackedDirectory();
	if (msg.find(trackedDir) != std::string::npos)
	{
		wprintf(L"%s\n\n", pRenderedContent);
		ParseEventXml(pRenderedContent);
	}

cleanup:

	if (pRenderedContent) 
	{
		free(pRenderedContent);
	}

	return status;
}


// The callback that receives the events that match the query criteria. 
DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent)
{
	UNREFERENCED_PARAMETER(pContext);

	DWORD status = ERROR_SUCCESS;

	switch (action)
	{
		// You should only get the EvtSubscribeActionError action if your subscription flags 
		// includes EvtSubscribeStrict and the channel contains missing event records.
	case EvtSubscribeActionError:
		if (ERROR_EVT_QUERY_RESULT_STALE == (DWORD)hEvent)
		{
			wprintf(L"The subscription callback was notified that event records are missing.\n");
			// Handle if this is an issue for your application.
		}
		else
		{
			wprintf(L"The subscription callback received the following Win32 error: %lu\n", (DWORD)hEvent);
		}
		break;

	case EvtSubscribeActionDeliver:
		if (ERROR_SUCCESS != (status = PrintEvent(hEvent)))
		{
			goto cleanup;
		}
		break;

	default:
		wprintf(L"SubscriptionCallback: Unknown action.\n");
	}

cleanup:

	if (ERROR_SUCCESS != status)
	{
		// End subscription - Use some kind of IPC mechanism to signal
		// your application to close the subscription handle.
	}

	return status; // The service ignores the returned status.
}




void EventsSubscriber() 
{
	std::wcout << L"Subscribe events related to " << getCurrentMonitor().getTrackedDirectory() << L" started!" << std::endl;
	DWORD status = ERROR_SUCCESS;
	EVT_HANDLE hSubscription = NULL;
	LPWSTR pwsPath = L"Security";
	LPWSTR pwsQuery = L"Event/System[EventID=4663]";

	// Subscribe to events beginning with the oldest event in the channel. The subscription
	// will return all current events in the channel and any future events that are raised
	// while the application is active.
	hSubscription = EvtSubscribe(NULL, NULL, pwsPath, pwsQuery, NULL, NULL,
		(EVT_SUBSCRIBE_CALLBACK)SubscriptionCallback, EvtSubscribeStartAtOldestRecord);
	if (NULL == hSubscription)
	{
		status = GetLastError();

		if (ERROR_EVT_CHANNEL_NOT_FOUND == status)
			wprintf(L"Channel %s was not found.\n", pwsPath);
		else if (ERROR_EVT_INVALID_QUERY == status)
			// You can call EvtGetExtendedStatus to get information as to why the query is not valid.
			wprintf(L"The query \"%s\" is not valid.\n", pwsQuery);
		else
			wprintf(L"EvtSubscribe failed with %lu.\n", status);

		goto cleanup;
	}

	Sleep(5 * 60 * 1000);

cleanup:

	if (hSubscription)
		EvtClose(hSubscription);
}


