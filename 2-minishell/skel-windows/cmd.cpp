#include "cmd.h"
#include "parser.h"
#include "utils.h"
#include <iostream>
#include <memory>
#include <windows.h>

static HANDLE
create_process(const std::string &command, HANDLE hStdin, HANDLE hStdout,
               HANDLE hStdErr) {
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdInput = hStdin;
    si.hStdOutput = hStdout;
    si.hStdError = hStdErr;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    BOOL ret = CreateProcess(nullptr, const_cast<LPSTR>(command.c_str()),
                             nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si,
                             &pi);
    if (ret == FALSE) {
        std::cerr << "Execution failed for '" << command << "'" << std::endl;
        return nullptr;
    }

    return pi.hProcess;
}

static void close_in(HANDLE in) {
    if (in != GetStdHandle(STD_INPUT_HANDLE)) {
        BOOL ret = CloseHandle(in);
        DIE(ret == FALSE, "CloseHandle in");
    }
}

static void close_out(HANDLE out) {
    if (out != GetStdHandle(STD_OUTPUT_HANDLE)) {
        BOOL ret = CloseHandle(out);
        DIE(ret == FALSE, "CloseHandle out");
    }
}

static void close_err(HANDLE err, HANDLE out) {
    if (err != GetStdHandle(STD_ERROR_HANDLE) && err != out) {
        BOOL ret = CloseHandle(err);
        DIE(ret == FALSE, "CloseHandle err");
    }
}

static HANDLE
create_file(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
            DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes) {
    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.bInheritHandle = TRUE;
    return CreateFile(lpFileName, dwDesiredAccess, dwShareMode, &sa,
                      dwCreationDisposition, dwFlagsAndAttributes, nullptr);
}

static HANDLE create_out(const char *filename, bool append) {
    HANDLE h = create_file(filename, GENERIC_WRITE | GENERIC_READ,
                           FILE_SHARE_WRITE | FILE_SHARE_READ,
                           append ? OPEN_ALWAYS : CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL);
    DIE(h == INVALID_HANDLE_VALUE, "CreateFile out");

    if (append) {
        DWORD pos = SetFilePointer(h, 0, nullptr, FILE_END);
        DIE(pos == INVALID_SET_FILE_POINTER, "SetFilePointer out");
    }

    return h;
}

static void
redirect(const simple_command_t &s, HANDLE &hStdInput, HANDLE &hStdOutput,
         HANDLE &hStdError) {
    std::string in(get_word(s.in));
    if (!in.empty()) {
        close_in(hStdInput);
        hStdInput = create_file(in.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL);
        DIE(hStdInput == INVALID_HANDLE_VALUE, "CreateFile in");
    }

    std::string out(get_word(s.out));
    if (!out.empty()) {
        close_out(hStdOutput);
        hStdOutput = create_out(out.c_str(),
                                static_cast<bool>(s.io_flags & IO_OUT_APPEND));
    }

    std::string err(get_word(s.err));
    if (!err.empty()) {
        close_err(hStdError, hStdOutput);
        if (!out.empty() && out == err) {
            hStdError = hStdOutput;
        } else {
            hStdError = create_out(err.c_str(), static_cast<bool>(s.io_flags &
                                                                  IO_ERR_APPEND));
        }
    }
}

static void close_handles(HANDLE in, HANDLE out, HANDLE err) {
    close_err(err, out);
    close_out(out);
    close_in(in);
}

static DWORD
execute(const simple_command_t &s, HANDLE hStdInput, HANDLE hStdOutput,
        HANDLE hStdError, HANDLE &hProcess) {
    std::string command(get_argv(s));

    if (command == "exit" || command == "quit") {
        return SHELL_EXIT;
    }

    if (s.verb->next_part != nullptr &&
        strcmp(s.verb->next_part->string, "=") == 0) {
        BOOL bRet = SetEnvironmentVariable(s.verb->string,
                                           s.verb->next_part->next_part->string);
        return bRet == FALSE ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    if (get_word(s.verb) == "cd") {
        BOOL bRet = SetCurrentDirectory(get_word(s.params).c_str());
        return bRet == FALSE ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    hProcess = create_process(command, hStdInput, hStdOutput, hStdError);
    return hProcess == nullptr ? EXIT_FAILURE : EXIT_SUCCESS;
}

static DWORD
parse_simple(const simple_command_t &s, HANDLE in, HANDLE out, bool wait) {
    HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
    redirect(s, in, out, err);

    HANDLE hProcess = nullptr;
    DWORD exitStatus = execute(s, in, out, err, hProcess);
    close_handles(in, out, err);

    if (hProcess == nullptr) {
        return exitStatus;
    }

    if (!wait) {
        return EXIT_SUCCESS;
    }

    DWORD dwRes = WaitForSingleObject(hProcess, INFINITE);
    DIE(dwRes == WAIT_FAILED, "WaitForSingleObject");

    BOOL bRes = GetExitCodeProcess(hProcess, &dwRes);
    DIE(bRes == FALSE, "GetExitCodeProcess");

    bRes = CloseHandle(hProcess);
    DIE(bRes == FALSE, "CloseHandle");

    return dwRes;
}

static DWORD
do_on_pipe(command_t *cmd1, command_t *cmd2, HANDLE hStdin, HANDLE hStdout) {
    HANDLE readPipe;
    HANDLE writePipe;
    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.bInheritHandle = TRUE;
    BOOL ret = CreatePipe(&readPipe, &writePipe, &sa, 0);
    DIE(ret == FALSE, "CreatePipe");

    parse_command(cmd1, hStdin, writePipe, false);

    return parse_command(cmd2, readPipe, hStdout, true);
}

struct arg {
    command_t *c;
    HANDLE hStdin;
    HANDLE hStdout;
    bool wait;
};

static DWORD WINAPI ThreadFunc(LPVOID lpParameter) {
    auto *args = static_cast<arg *>(lpParameter);
    parse_command(args->c, args->hStdin, args->hStdout, args->wait);
    free(args);
    return EXIT_SUCCESS;
}

static char *clone_string(const char *string) {
    if (string == nullptr) {
        return nullptr;
    }
    return strdup(string);
}

static word_t *clone_word(const word_t *word) {
    if (word == nullptr) {
        return nullptr;
    }
    auto copy = new word_t;
    copy->string = clone_string(word->string);
    copy->expand = word->expand;
    copy->next_part = clone_word(word->next_part);
    copy->next_word = clone_word(word->next_word);
    return copy;
}

static simple_command_t *
clone_simple_command(const simple_command_t *simple_command,
                     struct command_t *up) {
    if (simple_command == nullptr) {
        return nullptr;
    }
    auto copy = new simple_command_t;
    copy->verb = clone_word(simple_command->verb);
    copy->params = clone_word(simple_command->params);
    copy->in = clone_word(simple_command->in);
    copy->out = clone_word(simple_command->out);
    copy->err = clone_word(simple_command->err);
    copy->io_flags = simple_command->io_flags;
    copy->up = up;
    return copy;
}

static command_t *clone_command(const command_t *c, command_t *up) {
    if (c == nullptr) {
        return nullptr;
    }
    auto copy = new command_t;
    copy->up = up;
    copy->cmd1 = clone_command(c->cmd1, copy);
    copy->cmd2 = clone_command(c->cmd2, copy);
    copy->op = c->op;
    copy->scmd = clone_simple_command(c->scmd, copy);
    return copy;
}

static void
parse_async(command_t *c, HANDLE hStdin, HANDLE hStdout, bool wait) {
    auto args = new arg;
    args->c = clone_command(c, nullptr);
    args->hStdin = hStdin;
    args->hStdout = hStdout;
    args->wait = wait;
    HANDLE hThread = CreateThread(nullptr, 0, ThreadFunc, args, 0, nullptr);
    DIE(hThread == nullptr, "CreateThread");
}

DWORD parse_command(command_t *c, HANDLE hStdin, HANDLE hStdout, bool wait) {
    switch (c->op) {
    case OP_NONE:
        return parse_simple(*c->scmd, hStdin, hStdout, wait);
    case OP_SEQUENTIAL:
        parse_command(c->cmd1, hStdin, hStdout, true);
        return parse_command(c->cmd2, hStdin, hStdout, true);
    case OP_PARALLEL:
        parse_async(c->cmd1, hStdin, hStdout, true);
        return parse_command(c->cmd2, hStdin, hStdout, true);
    case OP_CONDITIONAL_NZERO: {
        DWORD ret = parse_command(c->cmd1, hStdin, hStdout, wait);
        if (ret == EXIT_SUCCESS) {
            return ret;
        }
        return parse_command(c->cmd2, hStdin, hStdout, wait);
    }
    case OP_CONDITIONAL_ZERO: {
        DWORD ret = parse_command(c->cmd1, hStdin, hStdout, wait);
        if (ret != EXIT_SUCCESS) {
            return ret;
        }
        return parse_command(c->cmd2, hStdin, hStdout, wait);
    }
    case OP_PIPE:
        return do_on_pipe(c->cmd1, c->cmd2, hStdin, hStdout);
    default:
        return SHELL_EXIT;
    }
}
