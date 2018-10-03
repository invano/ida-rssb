import sys
import struct
import string

code = []

def dispatch():
    ip = code[0]
    if code[ip] == -1:
        return False

    code[1] = (code[code[ip]] - code[1])&0xffff
    code[1] = code[1] - 65536 if code[1] > 32767 else code[1]
    
    if code[ip] != 2:
        code[code[ip]] = code[1]

    if code[1] < 0:
        return True
    return False

def exec_vm(size):
    while code[0] <= size:
        if code[code[0]] == -2:
            break
        
        if dispatch():
            code[0] += 1
        code[0] += 1
        
        if code[6] == 1:
            code[6] = 0
            sys.stdout.write(chr(code[4]))
            code[4] = 0
        if code[5] == 1:
            code[5] = 0
            code[3] = ord(sys.stdin.read(1))

def rssb(fin, key=None):
    with open(fin, "rb") as f:
        dd = f.read()
    
    for i in range(0, len(dd), 2):
        code.append(struct.unpack("<h", dd[i:i+2])[0])

    if key:
        for i in range(len(key)):
            code[0x10e+i] = ord(key[i])
    
    exec_vm(len(dd))

if __name__ == '__main__':
    flag = "Av0cad0_Love_2018@flare-on.com"
    rssb(sys.argv[1], flag)
