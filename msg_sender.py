from utilities import Msgq, MsgBufferIn, generate_key_pair
import ctypes

QUEUE_KEY = 108

# Generate key pair

rsa_key, public_key = generate_key_pair()

# Send message

queue = Msgq(QUEUE_KEY)

buffer = MsgBufferIn()
buffer.recipient = 1
buffer.process_id = 33 # os.getpid()
buffer.set_operation_type('k')
buffer.set_content('Hello world')

buffer.sign_message(rsa_key)
print("Verification:", buffer.verify_signature(public_key))

queue.send(buffer)
