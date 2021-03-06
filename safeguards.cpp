#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <openssl/rsa.h>

#include <thread>
#include <unordered_map>
#include <vector>
#include <mutex>

#include <iostream>

#include "z3++.h"

#include "safeguards.hpp"
#include <chrono>

#include <sys/time.h>
#include <time.h>
#include <math.h>
using namespace std::chrono;

int numGuardsInstalled = 0;

RSA *rsa_key;
char *pem_public_key;

int queue_id;

std::unordered_map<long, Process> processes;
std::vector<long> process_ids;
std::unordered_map<std::string, unsigned> removed_guard_versions;

std::mutex op_mtx;
std::mutex sig_mtx;

std::string guard_to_str(Guard guard, std::string guard_key) {
    std::string guard_str = guard_key;
    for (unsigned i = 0; i < guard.permissions.size(); i++) {
        guard_str += " " + std::to_string(guard.permissions[i]);
    }
    for (unsigned i = 0; i < guard.guard_lines.size(); i++) {
        guard_str += "\n";
        GuardLine *guard_line = &guard.guard_lines[i];

        if (guard_line->op == equal) guard_str += "=";
        else if (guard_line->op == not_equal) guard_str += "!=";
        else if (guard_line->op == greater_or_equal) guard_str += ">=";
        else if (guard_line->op == greater) guard_str += ">";
        else if (guard_line->op == smaller_or_equal) guard_str += "<=";
        else if (guard_line->op == smaller) guard_str += "<";
        else if (guard_line->op == cidr_in) guard_str += "IN";
        else if (guard_line->op == guard_if) guard_str += "IF";
        else if (guard_line->op == bool_and) guard_str += "AND";
        else if (guard_line->op == bool_or) guard_str += "OR";
        else if (guard_line->op == bool_xor) guard_str += "XOR";
        else if (guard_line->op == bool_not) guard_str += "NOT";
        else if (guard_line->op == plus) guard_str += "+";
        else if (guard_line->op == minus) guard_str += "-";
        else if (guard_line->op == multiply) guard_str += "*";
        else if (guard_line->op == divide) guard_str += "/";
        else if (guard_line->op == modulus) guard_str += "%";

        for (unsigned j = 0; j < MAX_PARAMETERS; j++) {
            switch (guard_line->type[j]) {
                case expression:
                    guard_str += " ";
                    guard_str += "^" + std::to_string(guard_line->values[j]);
                    break;
                case variable:
                    guard_str += " ";
                    guard_str += variables[guard_line->values[j]];
                    break;
                case integer:
                    guard_str += " ";
                    guard_str += std::to_string(guard_line->values[j]);
                    break;
            }
        }
    }
    return guard_str;
}

int parse_operation(GuardLine* line, char* message, int start)
{
    char* opStart = message + start;

    enum Operators op = op_fail;
    if (stringEqual(opStart, "=")) op = equal;
    else if (stringEqual(opStart, "!=")) op = not_equal;
    else if (stringEqual(opStart, ">=")) op = greater_or_equal;
    else if (stringEqual(opStart, ">")) op = greater;
    else if (stringEqual(opStart, "<=")) op = smaller_or_equal;
    else if (stringEqual(opStart, "<")) op = smaller;
    else if (stringEqual(opStart, "IN")) op = cidr_in;
    else if (stringEqual(opStart, "IF")) op = guard_if;
    else if (stringEqual(opStart, "AND")) op = bool_and;
    else if (stringEqual(opStart, "OR")) op = bool_or;
    else if (stringEqual(opStart, "XOR")) op = bool_xor;
    else if (stringEqual(opStart, "NOT")) op = bool_not;
    else if (stringEqual(opStart, "+")) op = plus;
    else if (stringEqual(opStart, "-")) op = minus;
    else if (stringEqual(opStart, "*")) op = multiply;
    else if (stringEqual(opStart, "/")) op = divide;
    else if (stringEqual(opStart, "%")) op = modulus;

    if (op == op_fail) {
        std::cerr << "Syntax error 01" << std::endl;
        return -1;
    }
    line->op = op;
    return 0;
}

int parse_value(GuardLine* line, int param_num, char* message, int start)
{
    char* varStart = message + start;
    int val = 0;

    // Check if expression starts with ^
    if (varStart[0] == '^')
    {
        varStart += 1;
        // ERROR CONDITIONS
        if (parseNumber(varStart, &val) == -1) {
            std::cerr << "Syntax error 02" << std::endl;
            return -1;
        }
        if (val >= line->lineNumber) {
            std::cerr << "Syntax error 03" << std::endl;
            return -1;
        }
        if (val < 0) {
            std::cerr << "Syntax error 04" << std::endl;
            return -1;
        }

        line->type[param_num] = expression;
        line->values[param_num] = val;
        return 0;
    }

    // TRY to read parameter as number
    if (parseNumber(varStart, &val) != -1)
    {
        line->type[param_num] = integer;
        line->values[param_num] = val;
        return 0;
    }
    
    for (int i = 0; i < variableCount; i++)
    {
        if (stringEqual(varStart, variables[i]))
        {
            line->type[param_num] = variable;
            line->values[param_num] = i;
            return 0;
        }
    }

    // The parameter matches no known variable, expression or integer
    std::cerr << "Syntax error 05" << std::endl;
    return -1;
}

int parse_line(GuardLine* line, char* message, int start, int end)
{
    int parameterStart = start;
    int parameterCount = 0;

    for (int i = start; i <= end; i++)
    {
        if (message[i] == ' ' ||
            message[i] == '\n' ||
            message[i] == '\0')
        {
            // Fail if the line is not parsed right (CIDR has an extra param for simplicity)
            if (parameterCount > MAX_PARAMETERS) {
                std::cerr << "Syntax error 06" << std::endl;
                return -1;
            }

            if (parameterCount == 0) {
                if (parse_operation(line, message, parameterStart) == -1) {
                    std::cerr << "Syntax error 07" << std::endl;
                    return -1;
                }
            }
            else {
                if (parse_value(line, parameterCount - 1, message, parameterStart) == -1) {
                    std::cerr << "Syntax error 08" << std::endl;
                    return -1;
                }
            }
            parameterCount++;
            parameterStart = i+1;
        }
    }
    while (parameterCount <= MAX_PARAMETERS) {
        line->type[parameterCount - 1] = unused;
        parameterCount++;
    }
    return 0;
}

void add_expressions(z3::context& c, Guard& g, std::vector<z3::expr>& exprVec)
{
    for (int i = 0; i < g.guard_lines.size(); i++)
    {
        GuardLine gl = g.guard_lines[i];
        z3::expr x = c.bv_val(0,32);

        if (gl.type[0] == expression) x = exprVec[gl.values[0]];
        if (gl.type[0] == variable) x = c.bv_const(variables[gl.values[0]],32);
        if (gl.type[0] == integer) x = c.bv_val(gl.values[0],32);

        // We process cidr_in separately
        if (gl.op == cidr_in)
        {
            int y = gl.values[1];
            int z = gl.values[2];

            int allOnes = numAllOnes(z);

            y = y & (~z);
            z = y + z;

            z3::expr newExp = x >= y && x <= z;
            exprVec.push_back(newExp);            
            continue;
        }

        z3::expr y = c.bv_val(0,32);
        if (gl.type[1] == expression) y = exprVec[gl.values[1]];
        if (gl.type[1] == variable) y = c.bv_const(variables[gl.values[1]],32);
        if (gl.type[1] == integer) y = c.bv_val(gl.values[1],32);

        // We also process if separately
        if (gl.op == guard_if)
        {
            z3::expr z = c.bv_val(0,32);
            if (gl.type[2] == expression) z = exprVec[gl.values[2]];
            if (gl.type[2] == variable) z = c.bv_const(variables[gl.values[2]],32);
            if (gl.type[2] == integer) z = c.bv_val(gl.values[2],32);

            z3::expr newExp = z3::ite(x,y,z);
            exprVec.push_back(newExp);            
            continue;
        }

        z3::expr newExp = c.bv_val(0,32);
        switch (gl.op)
        {
            case bool_and:
                newExp = x && y;
                break;
            case bool_or:
                newExp = x || y;
                break;
            case bool_xor:
                newExp = (!x) != (!y);
                break;
            case bool_not:
                newExp = !x;
                break;
            case equal:
                newExp = x == y;
                break;
            case not_equal:
                newExp = x != y;
                break;
            case greater:
                newExp = x > y;
                break;
            case greater_or_equal:
                newExp = x >= y;
                break;
            case smaller:
                newExp = x < y;
                break;
            case smaller_or_equal:
                newExp = x <= y;
                break;
            case plus:
                newExp = x + y;
                break;
            case minus:
                newExp = x - y;
                break;
            case multiply:
                newExp = x * y;
                break;
            case divide:
                newExp = x / y;
                break;
            case modulus:
                newExp = x % y;
        }

        exprVec.push_back(newExp);
    }
}

bool test_guards(Guard g1, Guard g2) {
    z3::context c;

    std::vector<z3::expr> pastExpressionsG1;
    std::vector<z3::expr> pastExpressionsG2;

    add_expressions(c, g1, pastExpressionsG1);
    add_expressions(c, g2, pastExpressionsG2);

    z3::solver s(c);
    s.add(pastExpressionsG1[g1.guard_lines.size()-1]);
    s.add(pastExpressionsG2[g2.guard_lines.size()-1]);

    if (s.check() == z3::unsat)
        return true; // NO CONFLICT
    else
        return false;
}

int parse_guard(char *message, Guard *new_guard, std::string *guard_key) {

    int lineStart = 0;
    int validEnd = FALSE;
    int lineNumber = 0;

    // Parse guard
    *guard_key = "";
    for (int i = 0; i < CONTENT_LEN; i++) {
        if (message[i] == '\n' || message[i] == '\0') {
            
            // Header
            if (guard_key->empty()) {
                if (i == 0) {
                    std::cerr << "Syntax error 09" << std::endl;
                    return -1;
                }
                std::string header(message, i);
                if (header.find('$') < header.length()) {
                    std::cerr << "Syntax error 00" << std::endl;
                    return -1;
                }
                std::stringstream header_stream(header);
                std::string guard_key_or_permission;
                while (std::getline(header_stream, guard_key_or_permission, ' ')) {
                    if (guard_key->empty()) {
                        *guard_key = guard_key_or_permission;
                    } else {
                        try {
                            new_guard->permissions.push_back(std::stol(guard_key_or_permission));
                            new_guard->permissions_pending.push_back(std::stol(guard_key_or_permission));
                        } catch (...) {
                            std::cerr << "Syntax error 10" << std::endl;
                            return -1;
                        }
                    }
                }
                lineStart = i+1;
                continue;
            }

            GuardLine guard_line;

            (guard_line).lineNumber = lineNumber;
            if (parse_line(&(guard_line), message, lineStart, i) == -1) {
                std::cerr << "Syntax error 11" << std::endl;
                return -1;
            }

            // Check that CIDR line uses only valid values for the second and third parameter
            if ((guard_line).op == cidr_in) {
                if ((guard_line).type[1] != integer) {
                    std::cerr << "Syntax error 12" << std::endl;
                    return -1;
                }
                if ((guard_line).type[2] != integer) {
                    std::cerr << "Syntax error 13" << std::endl;
                    return -1;
                }
                if ((guard_line).values[2] > 32 || (guard_line).values[2] < 0) {
                    std::cerr << "Syntax error 14" << std::endl;
                    return -1;
                }
            }

            new_guard->guard_lines.push_back(guard_line);

            lineStart = i+1;
            lineNumber++;

            if (message[i] == '\0') {
                validEnd = TRUE;
                break;
            }
        }
    }

    if (!validEnd) {
        std::cerr << "Syntax error 15" << std::endl;
        return -1;
    }

    return 0;

}

void send_response_msg(MsgBufferIn *buffer_in, char response_type, const char *content) {
    long recipient = buffer_in->process_id * 10000 + buffer_in->request_id;
    printf("Sending response message to %ld, response type %c, operation type %c\n\"%s\"\n",
        recipient,
        response_type,
        buffer_in->operation_type,
        content);
    MsgBufferOut buffer;
    buffer.recipient = recipient;
    buffer.response_type = response_type;
    buffer.operation_type = buffer_in->operation_type;
    strcpy(buffer.content, content);
    std::string message(1, response_type);
    message += buffer_in->operation_type;
    message += content;
    char *signature = signMessage(rsa_key, message);
    strcpy(buffer.response_sig, signature);
    // if (verifySignature(pem_public_key, message, buffer.response_sig))
    //     printf("Signature self-verification OK\n");
    // else
    //     printf("Signature self-verification failed\n");
    msgsnd(queue_id, &buffer, sizeof(buffer) - sizeof(long), 0);
}

void send_permission_msg(long process_id, char response_type, const char *content) {
    long recipient = process_id * 10000 + 1000000000;
        printf("Sending permission message to %ld, response type %c\n\"%s\"\n",
        recipient,
        response_type,
        content);
    MsgBufferOut buffer;
    buffer.recipient = recipient;
    buffer.response_type = response_type;
    buffer.operation_type = 'i';
    strcpy(buffer.content, content);
    std::string message(1, response_type);
    message += 'i';
    message += content;
    char *signature = signMessage(rsa_key, message);
    strcpy(buffer.response_sig, signature);
    msgsnd(queue_id, &buffer, sizeof(buffer) - sizeof(long), 0);
}

bool get_process_id_and_guard_key(MsgBufferIn *buffer, long *process_id, std::string *guard_key) {
    // Content format: pid guard-key
    // Example: 12345 https
    *process_id = -1;
    bool process_id_error = false;
    std::string getline_out;
    std::stringstream content_stream(buffer->content);
    while (std::getline(content_stream, getline_out, ' ')) {
        if (*process_id == -1) {
            try {
                *process_id = std::stol(getline_out);
            } catch (...) {
                process_id_error = true;
            }
        } else {
            *guard_key = getline_out;
            break;
        }
    }
    return !(process_id_error || guard_key->empty());
}

void op_public_key_exchange(Process *process, MsgBufferIn *buffer) {
    strcpy(process->public_key, buffer->content);
    printf("op_public_key_exchange: okay, view content\n");
    send_response_msg(buffer, 'v', pem_public_key);
}

void op_install_guard(Process *process, MsgBufferIn *buffer) {
    auto start = high_resolution_clock::now();
    
    char start_buffer[26];
    int millisec;
    struct tm* tm_info;
    struct timeval tv;

    gettimeofday(&tv, NULL);

    millisec = lrint(tv.tv_usec/1000.0); // Round to nearest millisec
    if (millisec>=1000) { // Allow for rounding up to nearest second
        millisec -=1000;
        tv.tv_sec++;
    }

    tm_info = localtime(&tv.tv_sec);

    strftime(start_buffer, 26, "%Y:%m:%d %H:%M:%S", tm_info);
    printf("Start: %s.%03d\n", start_buffer, millisec);

    Guard new_guard;
    std::string guard_key;

    if (parse_guard(buffer->content, &new_guard, &guard_key) == -1) {
        printf("op_install_guard: syntax error\n");
        send_response_msg(buffer, 'x', buffer->content);
        return;
    }

    // FIRST CRITICAL SECTION
    op_mtx.lock();
    std::vector<long> process_ids_copy = process_ids;
    std::unordered_map<long, Process> processes_copy = processes;
    op_mtx.unlock();

    // With guard parsed correctly, we proceed to run the guard on Z3 and evaluate if it conflicts.
    // If so, return guard key, as well as the process ID and guard key of the conflicting guard.
    for (unsigned i = 0; i < process_ids_copy.size(); i++) {
        bool skip_validation = false;
        for (unsigned j = 0; j < new_guard.permissions.size(); j++) {
            if (new_guard.permissions[j] == process_ids_copy[i]) {
                skip_validation = true;
                break;
            }
        }
        if (skip_validation || (process_ids_copy[i] == process->process_id))
            continue;
        Process *pr = &(processes_copy[process_ids_copy[i]]);
        for (unsigned j = 0; j < pr->guard_keys.size(); j++) {
            if (pr->guards[pr->guard_keys[j]].permissions_pending.size() == 0 &&
                !test_guards(pr->guards[pr->guard_keys[j]], new_guard)) {
                    std::string to_return = guard_key + " " + std::to_string(process_ids_copy[i]) + " " + pr->guard_keys[j];
                    printf("op_install_guard: conflict detected\n");
                    send_response_msg(buffer, 'c', to_return.c_str());
                    return;
            }
            if (new_guard.permissions.size() > 0) {
                std::string validated_guard_pid_and_key = std::to_string(process_ids_copy[i]) + "$" + pr->guard_keys[j];
                new_guard.validated_guard_versions[validated_guard_pid_and_key] = pr->guards[pr->guard_keys[j]].version;
            }
        }
    }

    // SECOND CRITICAL SECTION
    op_mtx.lock();

    // Set version number
    if (process->guards.count(guard_key)) {
        new_guard.version = process->guards[guard_key].version + 1;
    } else {
        std::string guard_pid_and_key = std::to_string(process->process_id) + "$" + guard_key;
        if (removed_guard_versions.count(guard_pid_and_key)) {
            new_guard.version = removed_guard_versions[guard_pid_and_key];
        } else {
            new_guard.version = 0;
        }
    }

    // Check if there are any new guards, evaluate for conflicts if so
    if (new_guard.permissions.size() == 0) {
        for (unsigned i = 0; i < process_ids.size(); i++) {
            if (process_ids[i] == process->process_id)
                continue;
            Process *pr = &(processes[process_ids[i]]);
            for (unsigned j = 0; j < pr->guard_keys.size(); j++) {
                if (processes_copy.count(process_ids[i]) == 0 ||
                    processes_copy[process_ids[i]].guards.count(pr->guard_keys[j]) == 0 ||
                    processes_copy[process_ids[i]].guards[pr->guard_keys[j]].version < pr->guards[pr->guard_keys[j]].version) {
                        if (pr->guards[pr->guard_keys[j]].permissions_pending.size() == 0) {
                            printf("Evaluating for conflicts, in critical section!!!!!\n");
                            if (!test_guards(pr->guards[pr->guard_keys[j]], new_guard)) {
                                std::string to_return = guard_key + " " + std::to_string(process_ids[i]) + " " + pr->guard_keys[j];
                                printf("op_install_guard: conflict detected\n");
                                send_response_msg(buffer, 'c', to_return.c_str());
                                op_mtx.unlock();
                                return;
                            }
                        }
                }
            }
        }
    }

    // Update or install guard
    process->guards[guard_key] = new_guard;
    if (new_guard.version == 0) {
        process->guard_keys.push_back(guard_key);
    }

    op_mtx.unlock();

    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(stop - start);
    std::cout << "Time taken by function: "
         << duration.count() << " microseconds" << std::endl;
    std::string s = "\nmicroseconds: " + std::to_string(duration.count());

    char stop_buffer[26];
    int stop_millisec;
    struct tm* stop_tm_info;
    struct timeval stop_tv;

    gettimeofday(&stop_tv, NULL);

    stop_millisec = lrint(stop_tv.tv_usec/1000.0); // Round to nearest millisec
    if (stop_millisec>=1000) { // Allow for rounding up to nearest second
        stop_millisec -=1000;
        stop_tv.tv_sec++;
    }

    stop_tm_info = localtime(&stop_tv.tv_sec);

    strftime(stop_buffer, 26, "%Y:%m:%d %H:%M:%S", stop_tm_info);
    printf("Stop: %s.%03d\n", stop_buffer, stop_millisec);

    char const *array2 = s.c_str();
    char * newArray = new char[strlen(buffer->content)+strlen(array2)+1];
    strcpy(newArray,buffer->content);
    strcat(newArray,array2);
    /*for(int i - 0 ; i < strlen(newArray) ; i ++ ){
      cout << "newArrray[i]" ;//Looping 5 times to print out [0],[1],[2],[3],[4]
    }*/

    if (new_guard.permissions.size() == 0) {
        printf("op_install_guard: okay\n");
        // send_response_msg(buffer, 'o', buffer->content);
        std::cout << buffer->content << std::endl;
        send_response_msg(buffer, 'o', newArray);
    } else {
        printf("op_install_guard: wait for permission\n");
        send_response_msg(buffer, 'w', buffer->content);
        // Send permission messages
        std::string process_id_and_guard = std::to_string(process->process_id) + " " + buffer->content;
        for (unsigned i = 0; i < new_guard.permissions.size(); i++) {
            printf("op_install_guard: ask another process for permission\n");
            send_permission_msg(new_guard.permissions[i], 'p', process_id_and_guard.c_str());
        }
    }

}

void op_remove_guard(Process *process, MsgBufferIn *buffer) {
    std::string guard_key = std::string(buffer->content);
    Guard old_guard;

    try {
        old_guard = process->guards.at(guard_key);
    } catch (const std::out_of_range& error) {
        printf("op_remove_guard: other error (guard not found)\n");
        send_response_msg(buffer, 'e', buffer->content);
        return;
    }

    op_mtx.lock();

    // remember the version number of the removed guard
    std::string old_guard_pid_and_key = std::to_string(process->process_id) + "$" + guard_key;
    removed_guard_versions[old_guard_pid_and_key] = old_guard.version;

    // remvove guard key from the vector
    for (unsigned j = 0; j < process->guard_keys.size(); j++) {
        if (process->guard_keys[j].compare(guard_key) == 0) {
            process->guard_keys.erase(process->guard_keys.begin()+j);
        }
    }
    
    // remove guard from the unordered map guards
    process->guards.erase(guard_key);

    op_mtx.unlock();

    printf("op_remove_guard: okay\n");
    send_response_msg(buffer, 'o', buffer->content);
}

void op_process_bye(MsgBufferIn *buffer) {
    op_mtx.lock();
    for (unsigned i = 0; i < process_ids.size(); i++) {
        if (process_ids[i] == buffer->process_id) {
            process_ids.erase(process_ids.begin() + i);
        }
    }
    processes.erase(buffer->process_id);
    op_mtx.unlock();
    printf("op_process_bye: okay\n");
    send_response_msg(buffer, 'o', buffer->content);
}

void op_approve_permission(Process *process, MsgBufferIn *buffer) {
    // Look up guard
    long process_id;
    std::string guard_key;
    if (!get_process_id_and_guard_key(buffer, &process_id, &guard_key)) {
        printf("op_approve_permission: syntax error\n");
        send_response_msg(buffer, 'x', buffer->content);
    }
    op_mtx.lock();
    try {
        Process *proc = &processes.at(process_id);
        Guard *guard = &proc->guards.at(guard_key);
        // Remove process ID from pending permissions
        bool process_id_removed = false;
        for (unsigned i = 0; i < guard->permissions_pending.size(); i++) {
            if (guard->permissions_pending[i] == buffer->process_id) {
                guard->permissions_pending.erase(guard->permissions_pending.begin() + i);
                process_id_removed = true;
            }
        }
        // Error for process ID not found in pending permissions
        if (!process_id_removed) {
            printf("op_approve_permission: other error (permission not needed)\n");
            send_response_msg(buffer, 'e', buffer->content);
        } else {
            printf("op_approve_permission: okay\n");
            send_response_msg(buffer, 'o', buffer->content);
            // If no more pending permissions, validate against new/updated guards
            if (guard->permissions_pending.size() == 0) {
                for (unsigned i = 0; i < process_ids.size(); i++) {
                    bool skip_validation = false;
                    for (unsigned j = 0; j < guard->permissions.size(); j++) {
                        if (guard->permissions[j] == process_ids[i]) {
                            skip_validation = true;
                            break;
                        }
                    }
                    if (skip_validation || (process_ids[i] == process_id))
                        continue;
                    Process *pr = &(processes[process_ids[i]]);
                    for (unsigned j = 0; j < pr->guard_keys.size(); j++) {
                        std::string validated_guard_pid_and_key = std::to_string(process_ids[i]) + "$" + pr->guard_keys[j];
                        if (guard->validated_guard_versions.count(validated_guard_pid_and_key) == 0 || 
                            guard->validated_guard_versions[validated_guard_pid_and_key] < pr->guards[pr->guard_keys[j]].version) {
                                if (pr->guards[pr->guard_keys[j]].permissions_pending.size() == 0) {
                                    printf("Evaluating new guard during permission approval!!!\n");
                                    if (!test_guards(pr->guards[pr->guard_keys[j]], *guard)) {
                                        // Send conflict message
                                        std::string to_return = guard_key + " " + std::to_string(process_ids[i]) + " " + pr->guard_keys[j];
                                        printf("op_approve_permission: conflict detected\n");
                                        send_permission_msg(process_id, 'c', to_return.c_str());
                                        // Remove the guard
                                        std::string old_guard_pid_and_key = std::to_string(process_id) + "$" + guard_key;
                                        removed_guard_versions[old_guard_pid_and_key] = guard->version;
                                        for (unsigned j = 0; j < proc->guard_keys.size(); j++) {
                                            if (proc->guard_keys[j].compare(guard_key) == 0) {
                                                proc->guard_keys.erase(proc->guard_keys.begin()+j);
                                            }
                                        }
                                        proc->guards.erase(guard_key);
                                        op_mtx.unlock();
                                        return;
                                    }
                                }
                        }
                    }
                }
                printf("op_approve_permission: okay, view content\n");
                send_permission_msg(process_id, 'v', guard_key.c_str());
            }
        }
    } catch (const std::out_of_range& error) {
        printf("op_approve_permission: other error (guard not found)\n");
        send_response_msg(buffer, 'e', buffer->content);
    }
    op_mtx.unlock();
}

void op_deny_permission(Process *process, MsgBufferIn *buffer) {
    // Look up guard
    long process_id;
    std::string guard_key;
    if (!get_process_id_and_guard_key(buffer, &process_id, &guard_key)) {
        printf("op_deny_permission: syntax error\n");
        send_response_msg(buffer, 'x', buffer->content);
    }
    try {
        Process pr = processes.at(process_id);
        Guard guard = pr.guards.at(guard_key);
        for (unsigned i = 0; i < guard.permissions_pending.size(); i++) {
            if (guard.permissions_pending[i] == buffer->process_id) {
                std::string content = guard_key + " " + std::to_string(process->process_id);
                printf("op_deny_permission: permission denied\n");
                send_permission_msg(process_id, 'd', content.c_str());
                printf("op_deny_permission: okay\n");
                send_response_msg(buffer, 'o', buffer->content);
                return;
            }
        }
        printf("op_deny_permission: other error (permission not needed)\n");
        send_response_msg(buffer, 'e', buffer->content);
    } catch (const std::out_of_range& error) {
        printf("op_deny_permission: other error (guard not found)\n");
        send_response_msg(buffer, 'e', buffer->content);
    }
}

void op_list_process_ids(MsgBufferIn *buffer) {
    std::string process_ids_str_concat = "";
    for (unsigned i = 0; i < process_ids.size(); i++) {
        if (processes[process_ids[i]].guard_keys.empty()) {
            continue;
        }
        if (i > 0) {
            process_ids_str_concat += " ";
        }
        process_ids_str_concat += std::to_string(process_ids[i]);
    }
    printf("op_list_process_ids: okay, view content\n");
    send_response_msg(buffer, 'v', process_ids_str_concat.c_str());
}

void op_list_guard_keys(MsgBufferIn *buffer) {
    try {
        long process_id;
        try {
            process_id = std::stol(std::string(buffer->content));
        } catch (const std::invalid_argument& error) {
            printf("op_list_guard_keys: syntax error\n");
            send_response_msg(buffer, 'x', buffer->content);
            return;
        }
        Process process = processes.at(process_id);
        std::string guard_keys_concat = "";
        for (unsigned i = 0; i < process.guard_keys.size(); i++) {
            if (i > 0) {
                guard_keys_concat += " ";
            }
            guard_keys_concat += process.guard_keys[i];
        }
        printf("op_list_guard_keys: okay, view content\n");
        send_response_msg(buffer, 'v', guard_keys_concat.c_str());
    } catch (const std::out_of_range& error) {
        printf("op_list_guard_keys: other error (process ID not found)\n");
        send_response_msg(buffer, 'e', buffer->content);
    }
}

void op_get_guard(MsgBufferIn *buffer) {
    long process_id;
    std::string guard_key;
    if (!get_process_id_and_guard_key(buffer, &process_id, &guard_key)) {
        printf("op_get_guard: syntax error\n");
        send_response_msg(buffer, 'x', buffer->content);
    }
    try {
        Process process = processes.at(process_id);
        Guard guard = process.guards.at(guard_key);
        std::string guard_str = guard_to_str(guard, guard_key);
        send_response_msg(buffer, 'v', guard_str.c_str());
    } catch (const std::out_of_range& error) {
        printf("op_get_guard: other error (guard not found)\n");
        send_response_msg(buffer, 'e', buffer->content);
    }
}

void handle_msg(void *buf) {

    MsgBufferIn *buffer = (MsgBufferIn*)buf;
    printf("Received from %ld, request ID %d, operation type %c\n\"%s\"\n",
        buffer->process_id,
        buffer->request_id,
        buffer->operation_type,
        buffer->content);

    // Check request ID; ignore message if out of range
    if (buffer->request_id < 0 || buffer->request_id > 9999) {
        printf("Request ID is out of range; message ignored");
        return;
    }

    // Verify the signature
    bool valid_sig = false;
    sig_mtx.lock();
    try {
        Process process = processes.at(buffer->process_id);
        // Signature must be valid per stored key
        std::string message(1, buffer->operation_type);
        message += buffer->content;
        valid_sig = verifySignature(process.public_key, message, buffer->message_sig);
        if (valid_sig) printf("Signature valid\n");
    } catch (const std::out_of_range& error) {
        // Signature not enforced if operation type is 'k'
        if (buffer->operation_type == 'k') {
            Process process;
            process.process_id = buffer->process_id;
            processes[buffer->process_id] = process;
            process_ids.push_back(buffer->process_id);
            valid_sig = true;
        }
        printf("Signature not enforced\n");
    }
    sig_mtx.unlock();
    if (!valid_sig) {
        // Respond with response type 'm'
        printf("Signature fail\n");
        send_response_msg(buffer, 'm', buffer->content);
        return;
    }

    Process *process = &(processes[buffer->process_id]);

    // Match the operation type
    if (buffer->operation_type == 'k') {
        printf("Public key exchange\n");
        op_public_key_exchange(process, buffer);
    } else if (buffer->operation_type == 'i') {
        printf("Install or update guard\n");
        op_install_guard(process, buffer);
    } else if (buffer->operation_type == 'r') {
        printf("Remove guard\n");
        op_remove_guard(process, buffer);
    } else if (buffer->operation_type == 'b') {
        printf("Remove all of a process's guards and key\n");
        op_process_bye(buffer);
    } else if (buffer->operation_type == 'a') {
        printf("Approve permission\n");
        op_approve_permission(process, buffer);
    } else if (buffer->operation_type == 'd') {
        printf("Deny permission\n");
        op_deny_permission(process, buffer);
    } else if (buffer->operation_type == 'l') {
        printf("List all process IDs with installed guards\n");
        op_list_process_ids(buffer);
    } else if (buffer->operation_type == 'n') {
        printf("List all guard keys for process ID\n");
        op_list_guard_keys(buffer);
    } else if (buffer->operation_type == 'g') {
        printf("Get guard for process ID and guard key\n");
        op_get_guard(buffer);
    } else {
        printf("Invalid operation type\n");
        send_response_msg(buffer, 'x', buffer->content);
    }

}

int main() {

    // Initialize RSA key
    rsa_key = create_rsa_key();
    pem_public_key = rsa_to_pem_public_key(rsa_key);
    printf("%s", pem_public_key);

    // Create message queue
    queue_id = msgget(QUEUE_KEY, QUEUE_PERM | IPC_CREAT);
    if (queue_id == -1) {
        perror("Cannot initialize queue");
        exit(1);
    } else {
        printf("Initialized queue %d\n", queue_id);
    }

    // Listen for messages
    int msg_type = 1;
    MsgBufferIn buffer;
    while (1) {
        // The following line will wait for a message
        if (msgrcv(queue_id, &buffer, sizeof(buffer) - sizeof(long), msg_type, 0) == -1) {
            perror("Cannot read queue");
            sleep(5);
        }
        // Create a new thread to handle the message
        std::thread thread(handle_msg, &buffer);
        thread.detach();
    }
}
