#define CONTENT_LEN 2048
// #define MAX_GUARD_SIZE 32
// #define MAX_NUM_PERMISSIONS 32
// #define MAX_NUM_GUARDS 16

#define MAX_PARAMETERS 3

#define SIG_LEN 512
#define QUEUE_KEY 108
#define QUEUE_PERM 0600

#define TRUE 1
#define FALSE 0

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

// Guard definitions

enum Operators {
   op_fail,
   // Boolean Operators
   bool_and,
   bool_or,
   bool_xor,
   bool_not,

   // Predicates
   equal,
   not_equal,
   greater,
   greater_or_equal,
   smaller,
   smaller_or_equal,
   cidr_in, //will be implemented with ints and the above
   guard_if,

   // Functions
   plus,
   minus,
   multiply,
   divide,
   modulus
};

enum Parameter_Type {
   expression,
   variable,
   integer,
   unused
};

typedef struct GuardLine {
   int lineNumber;
   enum Operators op;

   // These keep track whether variables refer
   // to a past expression, a variable or a new value
   enum Parameter_Type type[MAX_PARAMETERS];
   int values[MAX_PARAMETERS];

} GuardLine;

typedef struct Guard {
   std::vector<long> permissions;
   std::vector<GuardLine> guard_lines;
   unsigned version;
} Guard;

const int variableCount = 35;
const char* variables[] =
   {"ip.ver", "ip.hlen", "ip.tos", "ip.tlen", "ip.identification",
   "ip.ffo_unused", "ip.df", "ip.mf", "ip.foffset", "ip.ttl",
   "ip.nextp", "ip.hchecksum", "ip.src", "ip.dst",
   "udp.sport", "udp.dport", "udp.length", "udp.crc",
   "tcp.src_port", "tcp.dst_port", "tcp.seq_num",
   "tcp.ack_num", "tcp.offset", "tcp.reserved", "tcp.flag_cwr",
   "tcp.flag_ece", "tcp.flag_urg", "tcp.flag_ack", "tcp.flag_psh",
   "tcp.flag_rst", "tcp.flag_syn", "tcp.flag_fin", "tcp.rcv_wnd",
   "tcp.flag_cksum", "tcp.urg_ptr"};


// CHAR ARRAY HELPER FUNCTIONS
// CAN ONLY PASS NULL, SPACE or NEWLINE
// CONTAINING STRINGS (else buffer overrun)
int stringEqual(char* str1, const char* str2)
{
    for (int i = 0; i < CONTENT_LEN; i++)
    {
        // Check they have the same length
        if (str1[i] == '\0' ||
            str1[i] == '\n' ||
            str1[i] == ' ')
        {
            if (str2[i] == '\0' ||
            str2[i] == '\n' ||
            str2[i] == ' ')
                return 1;
            else
                return 0;
        }

        // Fail if we see a difference
        if (str1[i] != str2[i])
            return 0;
    }
    return -1;
}

int parseNumber(char* str, int* num)
{
   int minus = FALSE;
   if (str[0] == '-')
   {
      minus = TRUE;
      str += 1;
   }

   for (int i = 0; i < CONTENT_LEN; i++)
   {
      // Check they have the same length
      if (str[i] == '\0' ||
         str[i] == '\n' ||
         str[i] == ' ')
      {
         if (minus)
            (*num) = -(*num);
         return 0;
      }

      // Fail if we see a non-num string
      if (str[i] < '0' || str[i] > '9')
         return -1;

      int val = str[i] - '0';

      // Return error in overflow
      if ((*num) > (*num) * 10 + val)
         return -1;
      (*num) = (*num) * 10 + val;
   }
   return -1;
}

int numAllOnes(int z) {
   int result = 0;

   for (int i = 0; i < z; i++)
   {
      result = result * 2 + 1;
   }

   return result;
}

// Process definition
typedef struct Process {
   long process_id;
   // Public keys are ~426 chars, but this is more futureproof
   char public_key[CONTENT_LEN];
   std::unordered_map<std::string, Guard> guards;
   std::vector<std::string> guard_keys;
} Process;

// Cryptography functions, see cryptography.cpp
RSA *create_rsa_key();
char *rsa_to_pem_public_key(RSA *rsa_key);
bool verifySignature(std::string publicKey, std::string plainText, char* signatureBase64);
char* signMessage(RSA *rsa_key, std::string plainText);
