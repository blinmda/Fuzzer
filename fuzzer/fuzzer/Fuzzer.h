#pragma once
#include <string>
#include <map>
#include <functional>
#include <iostream>
#include "Functions.h"

class Fuzzer
{
private:
	std::map<char, std::function<void(int)>> commandHandlers;
	Functions funcs;
public:
	Fuzzer();
	void RunFuzzer();
};

