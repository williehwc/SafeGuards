from utilities import Msgq, MsgBufferIn, MsgBufferOut, generate_key_pair
import ctypes
import sys
import time

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
    #print("Self-verification:", buffer.verify_signature(public_key))

    queue.send(buffer)
    #print("Message sent")

    # Receive message

    buffer = MsgBufferOut()
    queue.recv(buffer, msg_type=pid * 10000 + request_id)
    print("Received", buffer.get_content_readable())

    
    if public_key_safeguards is None:
        public_key_safeguards = buffer.content
    #print("Verification:", buffer.verify_signature(public_key_safeguards))
    
    numSeconds = 0

    if operation_type == "i":
        message = str(buffer.get_content_readable())

        secondsIndex = message.find("microseconds")

        secondsArray = message[secondsIndex:].split(":")

        numSeconds = int("".join(filter(str.isdigit, secondsArray[1])))
    
    return numSeconds

# processes
numProcesses = int(sys.argv[1])

# number of guards per variable
numGuards = int(sys.argv[2])

request_id = int(sys.argv[3])

# one variable
overallTime = 0

variables = "tcp.src_port\ntcp.dst_port\ntcp.seq_num\ntcp.ack_num\nip6.src_hi\nip6.src_lo\nip6.dst_hi\nip6.dst_lo\nudp.sport\nudp.dport"

variables = ["tcp.src_port", "tcp.dst_port", "tcp.seq_num", "tcp.ack_num", "ip6.src_hi", "ip6.src_lo", "ip6.dst_hi", "ip6.dst_lo", "udp.sport", "udp.dport"]
for process in range(numProcesses):
    #processTime = 0
    send_and_receive_message('k', public_key, request_id, process + 1)
    request_id += 1
    for guardNum in range(numGuards):
        lowerBound = str(process * numGuards * 2 + guardNum * 2)
        upperBound = str(process * numGuards * 2 + guardNum * 2 + 2)
        guard = "guard" + str(guardNum + 1) +" 123\n"
        for variable in variables:
            guard += "< " + lowerBound + " " + variable + "\n"
            guard += "> " + upperBound + " " + variable + "\n"
        # combine lower and upper bound for all variables
        for pairNum in range(len(variables)):
            guard += "AND ^" + str(2 * pairNum) + " ^" + str(2 * pairNum + 1) + "\n"
        # line to add
        baseNum = len(variables) * 2
        # cumulative line
        currentNum = len(variables) * 3
        guard += "AND ^" + str(baseNum) + " ^" + str(baseNum + 1) + "\n"
        baseNum = baseNum + 2
        while baseNum < len(variables) * 3:
            guard += "AND ^" + str(currentNum) + " ^" + str(baseNum) + "\n"
            currentNum += 1
            baseNum += 1
        guardTime = send_and_receive_message('i', guard, request_id, process + 1)
        request_id += 1
        print(guardTime)
        #processTime += guardTime
        overallTime += guardTime
    # done with processTime
    #overallTime += processTime

for process in range(numProcesses):
    request_id += 1
    for guardNum in range(numGuards):
        send_and_receive_message('r', 'guard' + str(guardNum + 1), request_id, process + 1)
        request_id += 1

overallTime = overallTime / 1000000
print("Num Processes:" + str(numProcesses) + ", Num Guards:" + str(numGuards)
+ " Overall Time:"  + str(overallTime) +  "Last Request ID: " + str(request_id))

sys.stdout.flush()
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
