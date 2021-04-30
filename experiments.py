from utilities import Msgq, MsgBufferIn, MsgBufferOut, generate_key_pair
import ctypes

QUEUE_KEY = 108
PROCESS_ID = 33 # os.getpid()

# Generate key pair

rsa_key, public_key = generate_key_pair()
public_key_safeguards = None
queue = Msgq(QUEUE_KEY)

# Functions

def send_and_receive_message(operation_type, content, request_id, pid):

    global public_key_safeguards

    # Send message

    buffer = MsgBufferIn()
    buffer.recipient = 1
    buffer.process_id = pid
    buffer.request_id = request_id
    buffer.set_operation_type(operation_type)
    buffer.set_content(content)

    buffer.sign_message(rsa_key)
    print("Self-verification:", buffer.verify_signature(public_key))

    queue.send(buffer)
    print("Message sent")

    # Receive message

    buffer = MsgBufferOut()
    queue.recv(buffer, msg_type=pid * 10000 + request_id)
    print("Received", buffer.get_content_readable())

    if public_key_safeguards is None:
        public_key_safeguards = buffer.content
    print("Verification:", buffer.verify_signature(public_key_safeguards))

# processes
numProcesses = 5

request_id = 0

# multiple guards per process
numGuards = 1

# one variable
for process in range(numProcesses):
    send_and_receive_message('k', public_key, 0, process + 1)
    for guardNum in range(numGuards):
        request_id += 1
        # HARDCODED same guard for every process but but no conflict detected
        lowerBound = str(process * numGuards + guardNum)
        upperBound = str(process * numGuards + guardNum + 1)
        #guard = "guard1 123\n+ 500 700\n> tcp.src_port ^0"
        guard = "guard" + str(guardNum + 1) +" 123\n"
        guard += "< " + lowerBound + " tcp.src_port\n"
        guard += "> " + upperBound + " tcp.src_port\n"
        guard += "AND ^0 ^1"
        send_and_receive_message('i', guard, request_id, process + 1)

# generate a graph



# one guard per process
'''for process in range(numProcesses):
    request_id += 1
    lowerBound = str(process)
    upperBound = str(process + 1)
    #guard = "guard1 123\n+ 500 700\n> tcp.src_port ^0"
    guard = "guard1 123\n"
    guard += "< " + lowerBound + " tcp.src_port\n"
    guard += "> " + upperBound + " tcp.src_port\n"
    guard += "AND ^0 ^1"
    print(guard)
    print(process)
    send_and_receive_message('k', public_key, 0, process + 1)
    send_and_receive_message('i', guard, request_id, process + 1)'''


'''request_id += 1
        lowerBound = str(process * numGuards + guardNum)
        upperBound = str(process * numGuards + guardNum + 1)
        #guard = "guard1 123\n+ 500 700\n> tcp.src_port ^0"
        guard = "guard" + str(guardNum + 1) + " 123\n"
        guard += "< " + lowerBound + " tcp.src_port\n"
        guard += "> " + upperBound + " tcp.src_port\n"
        guard += "AND ^0 ^1"
        print(guard)
        send_and_receive_message('i', guard, request_id)'''