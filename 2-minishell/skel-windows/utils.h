/**
 * Operating Systems 2013-2017 - Assignment 2
 *
 */

#ifndef _UTILS_H
#define _UTILS_H

#include "parser.h"
#include <stdio.h>
#include <string>
#include <windows.h>

/**
* Debug method, used by DIE macro.
*/
static VOID PrintLastError(const char *message) {
    CHAR errBuff[1024];

    FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK,
        NULL,
        GetLastError(),
        0,
        errBuff,
        sizeof(errBuff) - 1,
        NULL);

    fprintf(stderr, "%s: %s\n", message, errBuff);
}

/* useful macro for handling error codes */
#define DIE(assertion, call_description) \
        do { \
                if (assertion) { \
                        fprintf(stderr, "(%s, %s, %d): ", \
                                __FILE__, __FUNCTION__, __LINE__); \
                        PrintLastError(call_description); \
                        exit(EXIT_FAILURE); \
                } \
        } while (0)

/**
 * Concatenate parts of the word to obtain the command
 */
std::string get_word(const word_t *s);

/**
 * Parse arguments in order to succesfully process them using CreateProcess
 */
std::string get_argv(const simple_command_t &command);

#endif /* _UTILS_H */
