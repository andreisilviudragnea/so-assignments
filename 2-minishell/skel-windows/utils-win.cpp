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

/**
 * Concatenate parts of the word to obtain the command
 */
LPTSTR get_word(word_t *s) {
    LPTSTR string = nullptr;
    DWORD string_length = 0;

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

        DWORD substring_length = strlen(substring);

        string = static_cast<LPTSTR>(realloc(string,
                                             string_length + substring_length +
                                             1));
        if (string == nullptr) {
            return nullptr;
        }

        memset(string + string_length, 0, substring_length + 1);

        strcat(string, substring);
        string_length += substring_length;

        s = s->next_part;
    }

    return string;
}

/**
 * Parse arguments in order to succesfully process them using CreateProcess
 */
LPTSTR get_argv(const simple_command_t *command) {
    LPTSTR argv = nullptr;
    LPTSTR substring = nullptr;
    word_t *param;

    DWORD string_length = 0;
    DWORD substring_length = 0;

    argv = get_word(command->verb);
    DIE(argv == nullptr, "Error retrieving word.");

    string_length = strlen(argv);

    param = command->params;
    while (param != nullptr) {
        substring = get_word(param);
        substring_length = strlen(substring);

        argv = static_cast<LPTSTR>(realloc(argv,
                                           string_length + substring_length +
                                           4));
        DIE(argv == nullptr, "Error reallocating argv.");

        strcat(argv, " ");

        /* Surround parameters with ' ' */
        strcat(argv, "'");
        strcat(argv, substring);
        strcat(argv, "'");

        string_length += substring_length + 3;
        param = param->next_word;

        free(substring);
    }

    return argv;
}


