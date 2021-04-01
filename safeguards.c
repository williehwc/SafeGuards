#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define QUEUE_KEY 123
#define MSG_TEXT_LEN 500
#define PERMISSIONS 0600

// Message format
struct msg_buf {
   long msg_type;
   char msg_text[MSG_TEXT_LEN];
};

int main() {

    // Create message queue
    int queue_id = msgget(QUEUE_KEY, PERMISSIONS | IPC_CREAT);
    if (queue_id == -1) {
        perror("Cannot initialize queue");
        exit(1);
    } else {
        printf("Initialized queue %d\n", queue_id);
    }

    // Listen for messages
    int msg_count = 0;
    int msg_type = 1;
    struct msg_buf buffer;
    while (1) {
        // The following line will wait for a message
        if (msgrcv(queue_id, &buffer, sizeof(buffer.msg_text), msg_type, 0) == -1) {
            perror("Cannot read queue");
            exit(1);
        }
        printf("Received: %ld \"%s\"\n", buffer.msg_type, buffer.msg_text);
        // If the message is "end", break out of the loop
        int to_end = strcmp(buffer.msg_text, "end");
        if (to_end == 0)
            break;
        if (msg_count % 2 == 0) {
            buffer.msg_type = 3;
            strcpy(buffer.msg_text, "Got it");
            if (msgsnd(queue_id, &buffer, strlen(buffer.msg_text) + 1, 0) == -1)
                perror("Cannot send response");
        }
        msg_count++;
    }

}