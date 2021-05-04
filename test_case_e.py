from utilities import Msgq, MsgBufferIn, MsgBufferOut, generate_key_pair
import ctypes

QUEUE_KEY = 108
PROCESS_ID_OFFSET = 100

rsa_key1, public_key1 = generate_key_pair()
rsa_key2, public_key2 = generate_key_pair()
rsa_key3, public_key3 = generate_key_pair()
public_key_safeguards = None
queue = Msgq(QUEUE_KEY)

def send_and_receive_message(operation_type, content, request_id, process_id, rsa_key, public_key):

    global public_key_safeguards

    # Send message

    buffer = MsgBufferIn()
    buffer.recipient = 1
    buffer.process_id = process_id + PROCESS_ID_OFFSET
    buffer.request_id = request_id
    buffer.set_operation_type(operation_type)
    buffer.set_content(content)

    buffer.sign_message(rsa_key)
    # print("Self-verification:", buffer.verify_signature(public_key))

    queue.send(buffer)
    print("Message sent")

    # Receive message

    buffer = MsgBufferOut()
    queue.recv(buffer, msg_type=(process_id + PROCESS_ID_OFFSET) * 10000 + request_id)
    print("Received", buffer.get_content_readable())

    if public_key_safeguards is None:
        public_key_safeguards = buffer.content
    print("Verification:", buffer.verify_signature(public_key_safeguards))

def receive_permissions_message(process_id):
    buffer = MsgBufferOut()
    queue.recv(buffer, msg_type=(process_id + PROCESS_ID_OFFSET) * 10000 + 1000000000)
    print("Received*", buffer.get_content_readable())
    print("Verification:", buffer.verify_signature(public_key_safeguards))


send_and_receive_message('k', public_key1, 0, 1, rsa_key1, public_key1)
send_and_receive_message('k', public_key2, 0, 2, rsa_key2, public_key2)
send_and_receive_message('k', public_key3, 0, 3, rsa_key3, public_key3)

guard = "guard2\n= tcp.src_port 10"
send_and_receive_message('i', guard, 1, 2, rsa_key2, public_key2)

guard = "guard1 102\n= ip.ver 6"
send_and_receive_message('i', guard, 1, 1, rsa_key1, public_key1)

receive_permissions_message(2)

guard = "guard3\n= tcp.src_port 5"
send_and_receive_message('i', guard, 3, 3, rsa_key3, public_key3)

send_and_receive_message('d', '101 guard1', 2, 2, rsa_key2, public_key2)

receive_permissions_message(1)

input("Press Enter or Return to continue")

send_and_receive_message('n', '101', 4, 2, rsa_key2, public_key2)
send_and_receive_message('g', '101 guard1', 5, 3, rsa_key3, public_key3)
