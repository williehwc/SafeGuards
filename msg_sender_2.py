from utilities import Msgq, MsgBufferIn, MsgBufferOut, generate_key_pair
import ctypes

QUEUE_KEY = 108
PROCESS_ID = 55 # os.getpid()

# Generate key pair

rsa_key, public_key = generate_key_pair()
public_key_safeguards = None
queue = Msgq(QUEUE_KEY)

# Functions

def send_and_receive_message(operation_type, content, request_id):

    global public_key_safeguards

    # Send message

    buffer = MsgBufferIn()
    buffer.recipient = 1
    buffer.process_id = PROCESS_ID
    buffer.request_id = request_id
    buffer.set_operation_type(operation_type)
    buffer.set_content(content)

    buffer.sign_message(rsa_key)
    print("Self-verification:", buffer.verify_signature(public_key))

    queue.send(buffer)
    print("Message sent")

    # Receive message

    buffer = MsgBufferOut()
    queue.recv(buffer, msg_type=PROCESS_ID * 10000 + request_id)
    print("Received", buffer.get_content_readable())

    if public_key_safeguards is None:
        public_key_safeguards = buffer.content
    print("Verification:", buffer.verify_signature(public_key_safeguards))

# ========= HELLO =========

# Note: SafeGuards will not verify signature

send_and_receive_message('k', public_key, 0)

# ========= INSTALL A GUARD =========

guard = "guard3\n> tcp.dst_port 10\n< tcp.src_port 5\nOR ^0 ^1"
send_and_receive_message('i', guard, 1)

# ========= INSTALL ANOTHER GUARD =========

# guard = "guard2\n> tcp.src_port 20"
# send_and_receive_message('i', guard, 2)

# ========= UPDATE FIRST GUARD =========

# guard = "guard1 123\n+ 400 900\n= tcp.src_port ^0"
# send_and_receive_message('i', guard, 3)

# ========= LIST PROCESSES =========

send_and_receive_message('l', '', 4)

# ========= LIST GUARDS =========

send_and_receive_message('n', str(33), 5)

# ========= GET GUARD =========

send_and_receive_message('g', str(PROCESS_ID) + " guard3", 6)

# ========= REMOVE GUARDS =========

# send_and_receive_message('r', 'guard1', 7)
# send_and_receive_message('r', 'guard2', 8)

# ========= LIST PROCESSES =========

# send_and_receive_message('l', '', 9)

# ========= LIST GUARDS =========

# send_and_receive_message('n', str(PROCESS_ID), 10)

# ========= GET GUARD =========

# send_and_receive_message('g', str(PROCESS_ID) + " guard1", 11)

# ========= BYE =========

send_and_receive_message('b', '', 12)
