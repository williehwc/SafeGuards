# Based on https://github.com/jj4jj/pymsgq

import ctypes, os, sys

libc = ctypes.CDLL('libc.so.6', use_errno=True)
_msgget = libc.msgget
_msgsnd = libc.msgsnd
_msgrcv = libc.msgrcv
_msgctl = libc.msgctl
_ftok = libc.ftok

crypto = ctypes.cdll.LoadLibrary('./cryptography.so')
crypto.rsa_to_pem_public_key.restype = ctypes.c_char_p
crypto.verifySignatureC.restype = ctypes.c_bool
crypto.signMessageC.restype = ctypes.c_char_p

PERMISSIONS = 438 # 0666

CONTENT_LEN = 2048
SIG_LEN = 512

def generate_key_pair():
    rsa_key = crypto.create_rsa_key()
    public_key = crypto.rsa_to_pem_public_key(rsa_key)
    print("The public key is", public_key)
    return (rsa_key, public_key)

class MsgBuffer(ctypes.Structure):
    def set_operation_type(self, c):
        self.operation_type = ctypes.c_byte(ord(c))
    def set_content(self, s):
        for i, c in enumerate(s):
            self.content[i] = ctypes.c_byte(ord(c))

class MsgBufferIn(MsgBuffer):
    _fields_ = [
        ('recipient', ctypes.c_long),
        ('process_id', ctypes.c_long),
        ('message_sig', ctypes.c_byte*SIG_LEN),
        ('operation_type', ctypes.c_byte),
        ('content', ctypes.c_byte*CONTENT_LEN),
    ]
    def sign_message(self, rsa_key):
        message = (ctypes.c_byte * (CONTENT_LEN + 1))()
        message[0] = self.operation_type
        for i in range(CONTENT_LEN):
            message[i + 1] = self.content[i]
        signature = crypto.signMessageC(rsa_key, message)
        print(signature)
        for i, c in enumerate(signature):
            self.message_sig[i] = c

class MsgBufferOut(MsgBuffer):
    _fields_ = [
        ('recipient', ctypes.c_long),
        ('message_sig', ctypes.c_byte*SIG_LEN),
        ('response_type', ctypes.c_byte),
        ('operation_type', ctypes.c_byte),
        ('content', ctypes.c_byte*CONTENT_LEN),
    ]

# IN and OUT are from the POV of SafeGuards, not the sender

class Msgq(object):

    def __init__(self, key):
        # Connect to an existing queue
        self.mqid = _msgget(key, PERMISSIONS)
        if self.mqid < 0:
            raise Exception('create msgq error:%s' % (os.strerror(ctypes.get_errno())))
    
    def send(self, buff):
        err = _msgsnd(self.mqid, ctypes.byref(buff), ctypes.sizeof(MsgBufferIn) - ctypes.sizeof(ctypes.c_long), 0)
        if err < 0:
            eno = ctypes.get_errno()
            if eno == errno.EAGAIN:
                return -1
            if eno == errno.EINTR:
                return -2
            raise Exception('send msgq error:%s' % os.strerror(ctypes.get_errno()))
        return err
