#include "cmd.h"
#include "parser.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>


void parse_error(const char *str, const int where) {
    std::cerr << "Parse error near " << where << ": " << str << "\n";
}

static void start_shell() {
    for (;;) {
        std::cout << "> " << std::flush;

        std::string line;
        std::getline(std::cin, line);
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        command_t *root = nullptr;
        parse_line(line.c_str(), &root);
        if (root == nullptr) {
            continue;
        }

        int ret = parse_command(root, GetStdHandle(STD_INPUT_HANDLE),
                                GetStdHandle(STD_OUTPUT_HANDLE), true);
        if (ret == SHELL_EXIT) {
            break;
        }
    }
}

int main() {
    start_shell();
    return EXIT_SUCCESS;
}
