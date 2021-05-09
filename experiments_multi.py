from threading import Thread
from utilities import Msgq, MsgBufferIn, MsgBufferOut, generate_key_pair
import ctypes
import sys
import time
#-----------------------------------------------------------------------

QUEUE_KEY = 108

# Generate key pair

rsa_key, public_key = generate_key_pair()
public_key_safeguards = None
queue = Msgq(QUEUE_KEY)

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

class PrinterThread (Thread):
    
    def __init__(self, start, end, numGuards, request_id):
        Thread.__init__(self)
        self._start = start
        self._end = end
        self._numGuards = numGuards
        self._request_id = request_id

    # Functions
    def run(self):
        '''for i in range(10):
            print(self._color)
        print(self._color + ' thread terminated')'''
         # processes
        start = self._start

        end = self._end

        # multiple guards per processs
        numGuards = self._numGuards

        request_id = self._request_id

        # one variable
        overallTime = 0

        # change to set by thread
        for process in range(start, end):
            processTime = 0
            send_and_receive_message('k', public_key, request_id, process + 1)
            request_id += 1
            for guardNum in range(numGuards):
                lowerBound = str(process * numGuards * 2 + guardNum * 2)
                upperBound = str(process * numGuards * 2 + guardNum * 2 + 2)
                #guard = "guard1 123\n+ 500 700\n> tcp.src_port ^0"
                guard = "guard" + str(guardNum + 1) + "\n"
                guard += "< " + lowerBound + " tcp.src_port\n"
                guard += "> " + upperBound + " tcp.src_port\n"
                guard += "AND ^0 ^1"
                guardTime = send_and_receive_message('i', guard, request_id, process + 1)
                request_id += 1
                print(guardTime)
                overallTime += guardTime

        '''for process in range(numProcesses):
            request_id += 1
            for guardNum in range(numGuards):
                send_and_receive_message('r', 'guard' + str(guardNum + 1), request_id, process + 1)
                request_id += 1'''

        overallTime = overallTime / 1000000
        print("Start:" + str(start) + ", Num Guards:" + str(numGuards)
        + " Overall Time:"  + str(overallTime) +  "Last Request ID: " + str(request_id))
        
#-----------------------------------------------------------------------

def main():
    
    # process 1 and 2
    blueThread = PrinterThread(0, 2, 1, 0)
    # process 3 and 4
    redThread = PrinterThread(2, 4, 1, 20)
    
    blueThread.start()
    redThread.start()
    
    print('main thread terminated')

#-----------------------------------------------------------------------

if __name__ == '__main__':
    main()
