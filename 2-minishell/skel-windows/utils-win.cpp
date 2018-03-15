/**
 * Operating Systems 2013-2017 - Assignment 2
 *
 */

/* do not use UNICODE */
#undef _UNICODE
#undef UNICODE

#include "utils.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>

#define MAX_SIZE_ENVIRONMENT_VARIABLE 512

std::string get_word(const word_t *s) {
    std::string str;

    while (s != nullptr) {
        CHAR substring[MAX_SIZE_ENVIRONMENT_VARIABLE];
        if (s->expand) {
            DWORD dwRet = GetEnvironmentVariable(s->string, substring,
                                                 MAX_SIZE_ENVIRONMENT_VARIABLE);
            if (dwRet == FALSE) {
                strcpy(substring, "");
            }
        } else {
            strcpy(substring, s->string);
        }

        str += substring;

        s = s->next_part;
    }

    return str;
}

std::string get_argv(const simple_command_t &command) {
    std::string argv = get_word(command.verb);

    word_t *param = command.params;
    while (param != nullptr) {
        std::string substring = get_word(param);

        argv += " '";
        argv += substring;
        argv += "'";

        param = param->next_word;
    }

    return argv;
}


