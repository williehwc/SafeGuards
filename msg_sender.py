from msgqueue import Msgq, MsgBufferIn
import os, ctypes

QUEUE_KEY = 108

queue = Msgq(QUEUE_KEY)

buffer = MsgBufferIn()
buffer.recipient = 1
buffer.process_id = os.getpid()
buffer.operation_type = 'z'
buffer.set_content('Hello world')

queue.send(buffer)
