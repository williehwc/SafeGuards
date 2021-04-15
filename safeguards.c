#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "safeguards.h"

int numGuardsInstalled = 0;
Guard installedGuards[MAX_NUM_GUARDS];

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
}

void *handle_msg(void *buf) {
    MsgBufferIn *buffer = (MsgBufferIn*)buf;
    printf("Received: \"%s\"\n", buffer->content);
}

// Create private/public key pair
RSA *create_rsa_key() {
    RSA *rsa_key = RSA_new();
    BIGNUM *rsa_exponent = BN_new();
	BN_set_word(rsa_exponent, RSA_F4); // RSA_F4 = 65537
    int rsa_return = RSA_generate_key_ex(rsa_key, RSA_BITS, rsa_exponent, NULL);
    if (!rsa_return) {
        perror("Cannot generate RSA key pair");
    }
    return rsa_key;
}

// Convert public key to PEM format so it can be passed as a string
char *rsa_to_pem_public_key(RSA *rsa_key) {
    BIO *key_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(key_bio, rsa_key);
    int key_len = BIO_pending(key_bio);
    char *pem_public_key = calloc(key_len + 1, 1); // null-terminate
    BIO_read(key_bio, pem_public_key, key_len);
    BIO_free_all(key_bio);
    return pem_public_key;
}

int main() {

    // Initialize RSA key
    RSA *rsa_key = create_rsa_key();
    char *pem_public_key = rsa_to_pem_public_key(rsa_key);
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
        pthread_t *thread;
        if (pthread_create(thread, NULL, handle_msg, &buffer) != 0) {
            perror("Cannot create thread");
            sleep(5);
        }
    }

}