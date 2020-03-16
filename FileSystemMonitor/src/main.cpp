#include "Log\Log.h"
#include "EventLog\EventLog.h"

int main() {
	
	LOG("File System Monitor started");
	
	EventsSubscriber();
	
	return 0;
}

