#define _CRT_SECURE_NO_WARNINGS
#include "Functions.h"

Functions::Functions()
{
	buffer_size = 0;
	buffer_orig = NULL;

	exception[0xC0000005] = "EXCEPTION_ACCESS_VIOLATION";
	exception[0xC000008C] = "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
	exception[0x8000008D] = "EXCEPTION_FLT_DENORMAL_OPERAND";
	exception[0xC000008E] = "EXCEPTION_FLT_DIVIDE_BY_ZERO";
	exception[0xC000008F] = "EXCEPTION_FLT_INEXACT_RESULT";
	exception[0xC0000090] = "EXCEPTION_FLT_INVALID_OPERATION";
	exception[0xC0000091] = "EXCEPTION_FLT_OVERFLOW";
	exception[0xC0000092] = "EXCEPTION_FLT_STACK_CHECK";
	exception[0xC0000093] = "EXCEPTION_FLT_UNDERFLOW";
	exception[0xC0000094] = "EXCEPTION_INT_DIVIDE_BY_ZERO";
	exception[0xC0000095] = "EXCEPTION_INT_OVERFLOW";
	exception[0xC00000FD] = "EXCEPTION_STACK_OVERFLOW";
}

Functions::~Functions()
{
	free(buffer_orig);
}

void Functions::Add(int loop) //add 2^iteration bytes to the end
{
	int i = 0;
	int current_size = 0;

	for (; i < loop; i++) {
		FILE* output = fopen(Path_Config_File.c_str(), "r+b");
		if (buffer_orig && buffer_orig[buffer_size - 1] == '\0') {
			fseek(output, -1, SEEK_END);
			buffer_size--;
		}
		else
			fseek(output, 0, SEEK_END);

		std::cout << "\n[" << i + 1 << " of " << loop << "]" << std::endl;

		current_size = buffer_size + (int)pow(2, i);
		char* buffer_new = new char[current_size + 1];
		if (buffer_orig)
			memcpy(buffer_new, buffer_orig, buffer_size);

		char c;
		for (int j = buffer_size; j < current_size; j++) {
			c = char('a' + rand() % ('z' - 'a'));
			fwrite(&c, sizeof(char), 1, output);
			buffer_new[j] = c;
		}
		buffer_new[current_size] = '\0';

		fclose(output);

		int bl = Fuzzing();
		float per = (float)bl / (float)ORIG_BLOCKS;
		if (per >= 0)
			std::cout << "\nCoverage: " << per << std::endl;

		if (per >= 0.999) {
			buffer_size = current_size;
			if (buffer_orig) {
				buffer_orig = (char*)realloc(buffer_orig, (current_size + 1) * sizeof(char));
				memcpy(buffer_orig, buffer_new, buffer_size);
			}
		}
		else if (buffer_orig) {
			FILE* output = fopen(Path_Config_File.c_str(), "w+b");
			fwrite(buffer_orig, sizeof(char), buffer_size, output);
			fclose(output);
		}

		std::string del(100, '#');
		std::cout << std::endl << del << std::endl;

		delete[] buffer_new;
	}
}

void Functions::Change(int numBytes) //change bytes till numBytes
{
	if (numBytes < 0) numBytes = buffer_size;
	int i = 1, all = 0;
	int position = 0;
	unsigned int byte = 0;
	int bytesChange = 0;
	char* buffer_new = new char[buffer_size + 1];

	std::cout << "\nEnter byte: ";
	std::cin >> std::hex >> byte;

	while (std::cin.get() != '\n');

	std::cout << "\nEnter number of bytes to replace during one test: ";
	std::cin >> std::dec >> bytesChange;

	all = (numBytes / bytesChange);
	numBytes = all * bytesChange;
	for (; position < numBytes; position += bytesChange) {
		FILE* output = fopen(Path_Config_File.c_str(), "r+b");
		fseek(output, position, SEEK_SET);

		if (buffer_orig)
			memcpy(buffer_new, buffer_orig, buffer_size);

		for (int j = 0; j < bytesChange; j++) {
			fwrite(&byte, sizeof(char), 1, output);
			buffer_new[position + j] = byte;
		}

		fclose(output);
		std::cout << "\n[" << i << " of " << all << "]" << std::endl;

		int bl = Fuzzing();
		float per = (float)bl / (float)ORIG_BLOCKS;
		if (per >= 0)
			std::cout << "\nCoverage: " << per << std::endl;

		if (per >= 0.999) {
			memcpy(buffer_orig, buffer_new, buffer_size);
		}
		else if (buffer_orig) {
			FILE* output = fopen(Path_Config_File.c_str(), "w+b");
			fwrite(buffer_orig, sizeof(char), buffer_size, output);
			fclose(output);
		}

		std::string del(100, '#');
		std::cout << std::endl << del << std::endl;

		i++;
	}
	delete[] buffer_new;
}

void Functions::readConfig()
{
	std::ifstream input(Path_Config_File, std::ios::binary);
	if (input) {
		input.seekg(0, std::ios::end);
		buffer_size = input.tellg();
		input.seekg(0, std::ios::beg);

		buffer_orig = (char*)calloc(buffer_size + 1, sizeof(char));

		input.read(buffer_orig, buffer_size);
		input.close();
	}
}

int Functions::Fuzzing()
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.hStdOutput = NULL;
	si.dwFlags |= STARTF_USESTDHANDLES;

	if (CreateProcessA(Path_EXE.c_str(), NULL, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi) == false)
	{
		std::cout << "CreateProcess failed: " << GetLastError() << std::endl;
		return 0;
	}
	DEBUG_EVENT DebugEvent;
	while (1)
	{
		if (WaitForDebugEvent(&DebugEvent, 500) == 0)
		{
			if (GetLastError() != ERROR_SEM_TIMEOUT)
			{
				std::cout << "WaitForDebugEvent failed: " << GetLastError() << std::endl;
			}
			//coverage
			std::cout << "\nCorrect.\nCalculate coverage..." << std::endl;

			system("C:\\Users\\user\\Documents\\DynamoRIO\\bin32\\drrun.exe -t drcov"
				" -dump_text -- C:\\Users\\user\\Desktop\\mbks\\2\\vuln4.exe > NUL");

			WIN32_FIND_DATA FILEDATA;
			HANDLE hFile = FindFirstFile(L"drcov.vuln4.exe.*.0000.proc.log", &FILEDATA);

			if (hFile == INVALID_HANDLE_VALUE) {
				std::cout << "drcov.vuln4.exe.*.0000.proc.log file not found" << std::endl;
				return 0;
			}

			char* fileName = new char[wcslen(FILEDATA.cFileName) + 1]();
			wcstombs(fileName, FILEDATA.cFileName, wcslen(FILEDATA.cFileName));
			std::ifstream fp(fileName, std::ios::binary);
			std::string line;
			int Blocks = 0;

			if (fp) {
				while (std::getline(fp, line)) {
					size_t found = line.find("BB Table: ");
					if (found != std::string::npos) {
						Blocks = atoi((line.substr(found + 10).c_str()));
						break;
					}
				}
				fp.close();
			}
			remove(fileName);

			return Blocks;
		}
		if (DebugEvent.dwDebugEventCode != EXCEPTION_DEBUG_EVENT)
		{
			ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);
			continue;
		}

		if (exception.find(DebugEvent.u.Exception.ExceptionRecord.ExceptionCode) != exception.end()) {
			std::cout << "\nException: " << exception[DebugEvent.u.Exception.ExceptionRecord.ExceptionCode] << std::endl;
			std::cout << "\nLog file: " << std::to_string(DebugEvent.dwThreadId) + "_log.txt" << std::endl;
			getContext(DebugEvent, pi.hProcess);
			//create input file with buffer in such situation
			return -1;
		}
		else
			ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);
	}
	return 0;
}

void Functions::getContext(DEBUG_EVENT DebugEvent, HANDLE hProcess)
{
	HANDLE thread;
	WOW64_CONTEXT cont;

	thread = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEvent.dwThreadId);
	if (thread == NULL)
	{
		std::cout << "OpenThread failed: " << GetLastError() << std::endl;
		return;
	}

	cont.ContextFlags = CONTEXT_FULL;

	if (Wow64GetThreadContext(thread, &cont) == false)
	{
		std:: cout << "GetThreadContext failed: " << GetLastError() << std::endl;
		CloseHandle(thread);
		return;
	}

	std::string fName = std::to_string(DebugEvent.dwThreadId) + "_log.txt";
	FILE* log = fopen(fName.c_str(), "w");

	fprintf(log, "Exception: %s\n", exception[DebugEvent.u.Exception.ExceptionRecord.ExceptionCode].c_str());
	logNewConfig(log);

	fprintf(log, "\nRegisters:\n");
	fprintf(log, "EAX: 0x%08X\n", cont.Eax);
	fprintf(log, "EBX: 0x%08X\n", cont.Ebx);
	fprintf(log, "ECX: 0x%08X\n", cont.Ecx);
	fprintf(log, "EDX: 0x%08X\n", cont.Edx);
	fprintf(log, "EIP: 0x%08X\n", cont.Eip);
	fprintf(log, "ESP: 0x%08X\n", cont.Esp);
	fprintf(log, "EBP: 0x%08X\n", cont.Ebp);
	fprintf(log, "EDI: 0x%08X\n", cont.Edi);
	fprintf(log, "ESI: 0x%08X\n", cont.Esi);
	fprintf(log, "EFLAGS: 0x%08X\n", cont.EFlags);

	unsigned char stackData[4096] = { 0 };
	SIZE_T bytesRead;
	ReadProcessMemory(hProcess, (LPCVOID)cont.Esp, stackData, sizeof(stackData), &bytesRead);
	if (bytesRead != 0)
	{
		fprintf(log, "\nStack:");
		for (int i = 0; i < bytesRead; i++)
		{
			if (i % 32 == 0)
				fprintf(log, " \n");
			fprintf(log, "%02X ", stackData[i]);
		}
	}
	fprintf(log, "\n");
	fclose(log);
}

void Functions::logNewConfig(FILE* fp)
{
	int size = 0;
	char* buf = NULL;
	std::ifstream input(Path_Config_File, std::ios::binary);
	if (input) {
		input.seekg(0, std::ios::end);
		size = input.tellg();
		input.seekg(0, std::ios::beg);

		buf = new char [size+1]();

		input.read(buf, size);
		input.close();
	}

	fprintf(fp, "\nCurrent configuration file: \n");
	for (int i = 0; i < size; i++) {
		fprintf(fp, "%c", buf[i]);
	}
	fprintf(fp, "\n");
}
