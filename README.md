# File System Monitor
Windows file-system monitor which detects and logs changes made to the given files and directories. 
The file-system monitor gets a list of directories to monitor, and logs any changes made to the directory and all sub-directories and files to the console.

### Simple Usage
```cpp
StartMonitorDirectory(std::wstring(L"C:\\temp\\test\\test7"));
```

## How it works?
I used the Windows Audit Mechanism to track changes made to files/folders in the directory we tracked (this is implemeted [here](FileSystemMonitor/src/AccessAudit/AccessAudit.h) ).
In order to received events written to Event Log I created a subscriber which implemeted [here](FileSystemMonitor/src/EventLog/EventLog.h). The manager which start tracking each directory given is implemented [here](FileSystemMonitor/src/Monitor/MonitorDispatcher.h).


### Prerequisites
Visual Studio 2015

## Compile and Deployment:
This project was develop in Visual Studio 2019 in 64 bit. In order to run it:
* Build the project (Ctrl+Shift+B)
* Run it (Ctrl+F5)

## Future work
Still need to write the logs messages to file.

