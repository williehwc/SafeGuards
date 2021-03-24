#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define QUEUE_KEY 123
#define MSG_TEXT_LEN 500
#define PERMISSIONS 0600

// Message format
struct msg_buf {
   long msg_type;
   char msg_text[MSG_TEXT_LEN];
};

int main() {

    // Access message queue
    int queue_id = msgget(QUEUE_KEY, PERMISSIONS);
    if (queue_id == -1) {
        perror("Cannot access queue");
        exit(1);
    } else {
        printf("Accessed queue %d\n", queue_id);
    }

    // Send messages
    int msg_type = 0;
    struct msg_buf buffer;
    while(fgets(buffer.msg_text, sizeof buffer.msg_text, stdin) != NULL) {
        int len = strlen(buffer.msg_text);
        // Remove newline at end, if it exists
        if (buffer.msg_text[len-1] == '\n')
            buffer.msg_text[len-1] = '\0';
        if (msgsnd(queue_id, &buffer, len + 1, 0) == -1)
            perror("Cannot send message");
    }

}