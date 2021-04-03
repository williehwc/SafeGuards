#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "safeguards.h"

int main() {

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
            exit(1);
        }
        printf("Received: \"%s\"\n", buffer.msg_text);
        // If the message is "end", break out of the loop
        int to_end = strcmp(buffer.msg_text, "end");
        if (to_end == 0)
            break;
        sleep(1);
    }

}