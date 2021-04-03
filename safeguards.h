#define CONTENT_LEN 2048
#define SIG_LEN 64
#define QUEUE_KEY 108
#define QUEUE_PERM 0600

// Inbound messages to SafeGuards
typedef struct MsgBufferIn {
   long recipient;
   long process_id;
   char message_sig[SIG_LEN];
   char operation_type;
   char content[CONTENT_LEN];
} MsgBufferIn;

// Outbound messages from SafeGuards
typedef struct MsgBufferOut {
   long recipient;
   char response_sig[SIG_LEN];
   char response_type;
   char operation_type;
   char content[CONTENT_LEN];
} MsgBufferOut;

// For debugging/testing purposes
typedef struct MsgBufferDebug {
   long msg_type;
   char msg_text[CONTENT_LEN];
} MsgBufferDebug;