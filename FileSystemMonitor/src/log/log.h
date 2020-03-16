
#define LOG(...) LogWrapper(__FILE__, __LINE__, __VA_ARGS__)
#include <sstream>
#include <Windows.h>

template<typename... Args>
void LogWrapper(const char* file, int line, const Args&... args)
{
	std::ostringstream msg;
	LogRecursive(file, line, msg, args...);
}

template<typename T, typename... Args>
void LogRecursive(const char* file, int line, std::ostringstream& msg,
	T value, const Args&... args)
{
	msg << value;
	LogRecursive(file, line, msg, args...);
}

void LogRecursive(const char* file, int line, std::ostringstream& msg)
{
	std::ostringstream logLine;
	logLine << file << "(" << line << "): " << msg.str() << std::endl;
	OutputDebugStringA(logLine.str().c_str());
	printf(logLine.str().c_str());
}