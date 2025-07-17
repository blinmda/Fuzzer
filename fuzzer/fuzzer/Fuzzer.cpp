#define _CRT_SECURE_NO_WARNINGS
#include "Fuzzer.h"

Fuzzer::Fuzzer()
{
	commandHandlers['c'] = [this](int num) {
		funcs.Change(num);
	};

	commandHandlers['w'] = [this](int num) {
		funcs.Add(num);
	};

	commandHandlers['r'] = [this](int num) {
		funcs.Fuzzing();
	};

	commandHandlers['e'] = [this](int num) {
		exit(1);
	};

	commandHandlers['h'] = [this](int num) {
		std::cout <<
			"[c] <number of bytes> - auto-change bytes \n"
			"[w] <number of tests> - auto-write bytes to the end \n"

			"[h] - help \n"
			"[e] - exit" << std::endl;
	};
}

void Fuzzer::RunFuzzer()
{
	funcs.readConfig();

	std::cout <<
		"[c] <number of last byte> - auto-change bytes \n"
		"[w] <number of tests> - auto-write bytes to the end \n"
		"[r] - run program\n"
		"[h] - help \n"
		"[e] - exit" << std::endl;

	while (1) {
		std::cout << "\n# ";
		char choice;
		int number = 0;
		std::cin >> choice;
		if (choice == 'c' || choice == 'w')
			std::cin >> number;

		if (commandHandlers.find(choice) != commandHandlers.end())
			commandHandlers[choice](number);
	}
}
