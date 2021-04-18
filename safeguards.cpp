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

#include <iostream>

#include "safeguards.hpp"

int numGuardsInstalled = 0;
Guard installedGuards[MAX_NUM_GUARDS];

RSA *rsa_key;
char *pem_public_key;

std::unordered_map<long, Process> processes;

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
    else if (stringEqual(opStart, "AND")) op = bool_and;
    else if (stringEqual(opStart, "OR")) op = bool_or;
    else if (stringEqual(opStart, "XOR")) op = bool_xor;
    else if (stringEqual(opStart, "NOT")) op = bool_not;
    else if (stringEqual(opStart, "+")) op = plus;
    else if (stringEqual(opStart, "-")) op = minus;
    else if (stringEqual(opStart, "*")) op = multiply;
    else if (stringEqual(opStart, "/")) op = divide;
    else if (stringEqual(opStart, "%")) op = modulus;

    if (op == op_fail) return -1;
    line->op = op;
    return 0;
}

int parse_value(GuardLine* line, int param_num, char* message, int start)
{
    char* varStart = message + start;
    int val;

    // Check if expression starts with ^
    if (varStart[0] == '^')
    {
        varStart += 1;
        // ERROR CONDITIONS
        if (parseNumber(varStart, &val) == -1) return -1;
        if (val >= line->lineNumber) return -1;
        if (val < 0) return -1;

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
    return -1;
}

int parse_line(GuardLine* line, char* message, int start, int end)
{
    int parameterStart = 0;
    int parameterCount = 0;
    for (int i = start; i <= end; i++)
    {
        if (message[i] == ' ' ||
            message[i] == '\n' ||
            message[i] == '\0')
        {
            // Fail if the line is not parsed right
            if (parameterCount >= MAX_PARAMETERS)
                return -1;

            if (parameterCount == 0)
                if (parse_operation(line, message, parameterStart) == -1)
                    return -1;
            else
                if (parse_value(line, parameterCount, message, parameterStart) == -1)
                    return -1;
            parameterCount++;
        }
    }
    return 0;
}

int install_guard(char* message)
{
    int lineStart = 0;
    int validEnd = FALSE;
    int lineNumber = 0;

    Guard* newGuard = &installedGuards[numGuardsInstalled];
    for (int i = 0; i < CONTENT_LEN; i++)
    {
        if (message[i] == '\n' || message[i] == '\0')
        {
            (newGuard->guard[lineNumber]).lineNumber = lineNumber;
            if (parse_line(&(newGuard->guard[lineNumber]), message, lineStart, i) == -1)
                return -1;
            lineStart = i+1;
            lineNumber++;

            if (message[i] == '\0')
            {
                validEnd = TRUE;
                break;
            }
        }
    }
    if (!validEnd) return -1;

    // With guard parsed correctly, we proceed to run the guard on Z3 and evaluate if it conflicts

    // If it does, we return the process id of the conflicting process. Else, return 0.
    return 0;
}

void send_msg(long recipient, char response_type, char operation_type, char *content) {
    MsgBufferOut buffer;
    buffer.recipient = recipient;
    buffer.response_type = response_type;
    buffer.operation_type = operation_type;
    strcpy(buffer.content, content);
    std::string message(1, response_type);
    message += operation_type;
    message += content;
    char *signature = signMessage(rsa_key, message);
    // TODO
    msgsnd(recipient, &buffer, sizeof buffer, 0);
}

void handle_msg(void *buf) {

    MsgBufferIn *buffer = (MsgBufferIn*)buf;
    printf("Received from %ld, operation type %c\n\"%s\"\n",
        buffer->process_id,
        buffer->operation_type,
        buffer->content);

    // Verify the signature
    bool valid_sig = false;
    // try {
    //     Process process = processes.at(buffer->process_id);
    //     // Signature must be valid per stored key
    //     std::string message(1, buffer->operation_type);
    //     message += buffer->content;
    //     valid_sig = verifySignature(process.public_key, message, buffer->message_sig);
    // } catch (const std::out_of_range& error) {
    //     // Signature not enforced if operation type is 'k'
    //     if (buffer->operation_type == 'k') {
    //         Process process;
    //         process.process_id = buffer->process_id;
    //         processes[buffer->process_id] = process;
    //         valid_sig = true;
    //     }
    // }
    if (!valid_sig) {
        // Respond with response type 'm'
        // send_msg(buffer->process_id, 'm', buffer->operation_type, buffer->content);
        return;
    }

    // Match the operation type
    if (buffer->operation_type == 'k') {
        // Public key exchange
    } else if (buffer->operation_type == 'i') {
        // Install or update guard
    } else if (buffer->operation_type == 'r') {
        // Remove guard
    } else if (buffer->operation_type == 'b') {
        // Remove guard and key
    } else if (buffer->operation_type == 'a') {
        // Approve permission
    } else if (buffer->operation_type == 'd') {
        // Deny permission
    } else if (buffer->operation_type == 'l') {
        // List all process IDs with installed guards
    } else if (buffer->operation_type == 'g') {
        // Get guard for process ID
    } else {
        perror("Invalid operation type");
    }

}

int main() {

    // Initialize RSA key
    rsa_key = create_rsa_key();
    pem_public_key = rsa_to_pem_public_key(rsa_key);
    printf("%s", pem_public_key);

    // Create message queue
    int queue_id = msgget(QUEUE_KEY, QUEUE_PERM | IPC_CREAT);
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
