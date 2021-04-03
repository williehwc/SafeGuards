import pymsgq

QUEUE_KEY = 108

queue = pymsgq.Msgq(QUEUE_KEY)
queue.send("Hello world", 0)