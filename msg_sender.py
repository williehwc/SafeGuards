from utilities import Msgq, MsgBufferIn, MsgBufferOut, generate_key_pair
import ctypes

QUEUE_KEY = 108
PROCESS_ID = 33 # os.getpid()

# Generate key pair

rsa_key, public_key = generate_key_pair()

# Send message (SafeGuards will not verify signature)

queue = Msgq(QUEUE_KEY)

buffer = MsgBufferIn()
buffer.recipient = 1
buffer.process_id = PROCESS_ID
buffer.set_operation_type('k')
buffer.set_content(public_key)

buffer.sign_message(rsa_key)
print("Self-verification:", buffer.verify_signature(public_key))

queue.send(buffer)

# Receive message

buffer = MsgBufferOut()
queue.recv(buffer, msg_type=PROCESS_ID)
print("Received", buffer.get_content_readable())

public_key_safeguards = buffer.content
print("Verification:", buffer.verify_signature(public_key_safeguards))

# Send a second time (SafeGuards will verify signature)

buffer = MsgBufferIn()
buffer.recipient = 1
buffer.process_id = PROCESS_ID
buffer.set_operation_type('k')
buffer.set_content(public_key)

buffer.sign_message(rsa_key)
print("Self-verification:", buffer.verify_signature(public_key))

queue.send(buffer)
