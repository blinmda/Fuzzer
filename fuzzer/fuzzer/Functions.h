#pragma once
#include <string>
#include <iostream>
#include <windows.h> 
#include <fstream>
#include <map>
#include <stdio.h>
#include <cstdio>
#include <Windows.h>

#define ORIG_BLOCKS 5311

class Functions
{
private:
	std::string Path_Config_File = "C:\\Users\\user\\source\\repos\\fuzzer\\fuzzer\\config_4";
	std::string Path_EXE = "C:\\Users\\user\\source\\repos\\fuzzer\\fuzzer\\vuln4.exe";

	int buffer_size;
	char* buffer_orig;

	std::map<DWORD, std::string> exception;
public:

	Functions();
	~Functions();

	void Add(int loop);
	void Change(int loop);
	void readConfig();
	int Fuzzing();

	void getContext(DEBUG_EVENT DebugEvent, HANDLE hProcess);
	void logNewConfig(FILE* fp);
};

