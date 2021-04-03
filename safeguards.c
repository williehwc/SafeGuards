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

void *handle_msg(void *buf) {
    MsgBufferDebug *buffer = (MsgBufferDebug*)buf;
    printf("Received: \"%s\"\n", buffer->msg_text);
}

int main() {

    // Create private/public key pair
    RSA *rsa_key = RSA_new();
    BIGNUM *rsa_exponent = BN_new();
	BN_set_word(rsa_exponent, RSA_F4); // RSA_F4 = 65537
    int rsa_return = RSA_generate_key_ex(rsa_key, RSA_BITS, rsa_exponent, NULL);
    if (!rsa_return) {
        perror("Cannot generate RSA key pair");
        exit(1);
    }

    // Convert public key to PEM format so it can be passed as a string
    BIO *key_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(key_bio, rsa_key);
    int key_len = BIO_pending(key_bio);
    char *pem_public_key = calloc(key_len + 1, 1); // null-terminate
    BIO_read(key_bio, pem_public_key, key_len);
    BIO_free_all(key_bio);
    // printf("%s", pem_public_key);

    // Create message queue
    int queue_id = msgget(QUEUE_KEY, QUEUE_PERM | IPC_CREAT);
    if (queue_id == -1) {
        perror("Cannot initialize queue");
        exit(1);
    } else {
        printf("Initialized queue %d\n", queue_id);
    }

    // Listen for messages
    int msg_type = 0;
    MsgBufferDebug buffer;
    while (1) {
        // The following line will wait for a message
        if (msgrcv(queue_id, &buffer, sizeof(buffer.msg_text), msg_type, 0) == -1) {
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