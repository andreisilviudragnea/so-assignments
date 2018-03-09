#include <windows.h>
#include "cmd.h"
#include "utils.h"
#include "parser.h"

static HANDLE
create_process(LPSTR command, HANDLE hStdin, HANDLE hStdout, HANDLE hStdErr)
{
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdInput = hStdin;
    si.hStdOutput = hStdout;
    si.hStdError = hStdErr;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    BOOL ret = CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL,
                             &si, &pi);
    DIE(ret == FALSE, "CreateProcess");

    return pi.hProcess;
}

static void
redirect(const simple_command_t *s, PHANDLE hStdInput, PHANDLE hStdOutput,
         PHANDLE hStdError)
{
    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.bInheritHandle = TRUE;

    char *in = get_word(s->in);
    if (in != NULL) {
        *hStdInput = CreateFile(
            in,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &sa,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        free(in);
        DIE(*hStdInput == INVALID_HANDLE_VALUE, "CreateFile in");
    }

    char *out = get_word(s->out);
    if (out != NULL) {
        *hStdOutput = CreateFile(
            out,
            GENERIC_WRITE | GENERIC_READ,
            FILE_SHARE_WRITE | FILE_SHARE_READ,
            &sa,
            s->io_flags & IO_OUT_APPEND ? OPEN_ALWAYS : CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        DIE(*hStdOutput == INVALID_HANDLE_VALUE, "CreateFile out");
    }

    if (s->io_flags & IO_OUT_APPEND) {
        DWORD pos = SetFilePointer(*hStdOutput, 0, NULL, FILE_END);
        DIE(pos == INVALID_SET_FILE_POINTER, "SetFilePointer out");
    }

    char *err = get_word(s->err);
    if (err != NULL) {
        if (out != NULL && strcmp(out, err) == 0) {
            *hStdError = *hStdOutput;
        } else {
            *hStdError = CreateFile(
                err,
                GENERIC_WRITE | GENERIC_READ,
                FILE_SHARE_WRITE | FILE_SHARE_READ,
                &sa,
                s->io_flags & IO_ERR_APPEND ? OPEN_ALWAYS : CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );
        }
        free(err);
        DIE(*hStdError == INVALID_HANDLE_VALUE, "CreateFile err");
    }

    if (out != NULL) {
        free(out);
    }

    if (s->io_flags & IO_ERR_APPEND) {
        DWORD pos = SetFilePointer(*hStdError, 0, NULL, FILE_END);
        DIE(pos == INVALID_SET_FILE_POINTER, "SetFilePointer err");
    }
}

static HANDLE
execute_and_close_handles(const simple_command_t *s, HANDLE hStdInput,
                          HANDLE hStdOutput, HANDLE hStdError)
{
    HANDLE hProcess = create_process(get_argv(s), hStdInput, hStdOutput,
                                     hStdError);

    BOOL ret;

    if (hStdError != GetStdHandle(STD_ERROR_HANDLE) &&
        hStdError != hStdOutput) {
        ret = CloseHandle(hStdError);
        DIE(ret == FALSE, "CloseHandle err");
    }
    if (hStdOutput != GetStdHandle(STD_OUTPUT_HANDLE)) {
        ret = CloseHandle(hStdOutput);
        DIE(ret == FALSE, "CloseHandle out");
    }
    if (hStdInput != GetStdHandle(STD_INPUT_HANDLE)) {
        ret = CloseHandle(hStdInput);
        DIE(ret == FALSE, "CloseHandle in");
    }

    return hProcess;
}

static DWORD
parse_simple(simple_command_t *s, HANDLE hStdin, HANDLE hStdout, bool wait)
{
    char *command = get_argv(s);

    if (strcmp(command, "exit") == 0) {
        free(command);
        return SHELL_EXIT;
    }

    if (s->verb->next_part != NULL &&
        strcmp(s->verb->next_part->string, "=") == 0) {
        BOOL ret = SetEnvironmentVariable(s->verb->string,
                                          s->verb->next_part->next_part->string);
        return ret == FALSE ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    HANDLE hStdError = GetStdHandle(STD_ERROR_HANDLE);
    redirect(s, &hStdin, &hStdout, &hStdError);

    if (strcmp(get_word(s->verb), "cd") == 0) {
        BOOL ret = SetCurrentDirectory(get_word(s->params));
        return ret == FALSE ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    HANDLE hProcess = execute_and_close_handles(s, hStdin, hStdout, hStdError);

    if (!wait) {
        return EXIT_SUCCESS;
    }

    DWORD dwRes = WaitForSingleObject(hProcess, INFINITE);
    DIE(dwRes == WAIT_FAILED, "WaitForSingleObject");

    BOOL bRes = GetExitCodeProcess(hProcess, &dwRes);
    DIE(bRes == FALSE, "GetExitCode");

    return dwRes;
}

static DWORD
do_on_pipe(command_t *cmd2, HANDLE hStdin, HANDLE hStdout, command_t *cmd1)
{
    HANDLE readPipe;
    HANDLE writePipe;
    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(sa));
    sa.bInheritHandle = TRUE;
    BOOL ret = CreatePipe(&readPipe, &writePipe, &sa, 0);
    DIE(ret == FALSE, "CreatePipe");

    parse_command(cmd1, hStdin, writePipe, false);

    return parse_command(cmd2, readPipe, hStdout, true);
}

DWORD parse_command(command_t *c, HANDLE hStdin, HANDLE hStdout, bool wait)
{
    switch (c->op) {
    case OP_NONE:
        return parse_simple(c->scmd, hStdin, hStdout, wait);
    case OP_SEQUENTIAL:
        parse_command(c->cmd1, hStdin, hStdout, true);
        return parse_command(c->cmd2, hStdin, hStdout, true);
    case OP_PARALLEL:
        parse_command(c->cmd1, hStdin, hStdout, false);
        return parse_command(c->cmd2, hStdin, hStdout, true);
    case OP_CONDITIONAL_NZERO: {
        DWORD ret = parse_command(c->cmd1, hStdin, hStdout, true);
        if (ret == EXIT_SUCCESS) {
            return ret;
        } else {
            return parse_command(c->cmd2, hStdin, hStdout, true);
        }
    }
    case OP_CONDITIONAL_ZERO: {
        DWORD ret = parse_command(c->cmd1, hStdin, hStdout, true);
        if (ret != EXIT_SUCCESS) {
            return ret;
        } else {
            return parse_command(c->cmd2, hStdin, hStdout, true);
        }
    }
    case OP_PIPE:
        return do_on_pipe(c->cmd2, hStdin, hStdout, c->cmd1);
    default:
        return SHELL_EXIT;
    }
}
