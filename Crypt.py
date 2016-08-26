#coding:utf-8

from struct import pack as _pack
from struct import unpack as _unpack 
from binascii import b2a_hex, a2b_hex
from random import seed
from random import randint as _randint

__all__ = ['encrypt', 'decrypt']

seed()

op = 0xffffffffL

def xor(a, b):
    a1,a2 = _unpack('>LL', a[0:8])
    b1,b2 = _unpack('>LL', b[0:8])
    r = _pack('>LL', ( a1 ^ b1) & op, ( a2 ^ b2) & op)
    return r

def encipher(v, k):
    """
    TEA encipher encrypt 64 bits value, by 128 bits key,
    QQ do 16 round TEA.
    To see:
    http://www.ftp.cl.cam.ac.uk/ftp/papers/djw-rmn/djw-rmn-tea.html .
    TEA 加密,  64比特明码, 128比特密钥, qq的TEA算法使用16轮迭代
    具体参看
    http://www.ftp.cl.cam.ac.uk/ftp/papers/djw-rmn/djw-rmn-tea.html
    >>> c = encipher('abcdefgh', 'aaaabbbbccccdddd')
    >>> b2a_hex(c)
    'a557272c538d3e96'
    """
    n=16 
    delta = 0x9e3779b9L
    k = _unpack('>LLLL', k[0:16])
    y, z = _unpack('>LL', v[0:8])
    s = 0
    for i in xrange(n):
        s += delta
        y += (op &(z << 4))+ k[0] ^ z+ s ^ (op&(z >> 5)) + k[1]
        y &= op
        z += (op &(y << 4))+ k[2] ^ y+ s ^ (op&(y >> 5)) + k[3]
        z &= op
    r = _pack('>LL',y,z)
    return r

def decipher(v, k):
    """
    TEA decipher, decrypt  64bits value with 128 bits key.
    TEA 解密程序, 用128比特密钥, 解密64比特值
    """
    n = 16
    y, z = _unpack('>LL', v[0:8]) 
    a, b, c, d = _unpack('>LLLL', k[0:16])
    delta = 0x9E3779B9L
    s = (delta << 4)&op 
    for i in xrange(n):
        z -= ((y << 4) + c) ^ (y + s) ^ ((y >> 5) + d)
        z &= op
        y -= ((z << 4) + a) ^ (z + s) ^ ((z >> 5) + b)
        y &= op
        s -= delta
        s &= op
    return _pack('>LL', y, z)

def encrypt(v, k):
    """
    Encrypt Message follow QQ's rule.
    用QQ的规则加密消息
    参数 v 是被加密的明文, k是密钥
    >>> en = encrypt('', b2a_hex('b537a06cf3bcb33206237d7149c27bc3'))
    >>> decrypt(en,  b2a_hex('b537a06cf3bcb33206237d7149c27bc3'))
    """
    END_CHAR = '\0'
    FILL_N_OR = 0xF8
    vl = len(v)
    filln = (8-(vl+2))%8 + 2
    fills = ''
    for i in xrange(filln):
        fills = fills + chr(_randint(0, 0xff))
    v = ( chr((filln -2)|FILL_N_OR) + fills + v + END_CHAR * 7 )
    tr = '\0'*8
    to = '\0'*8
    r = ''
    o = '\0' * 8
    for i in xrange(0, len(v), 8):
        o = xor(v[i:i+8], tr)
        tr = xor( encipher(o, k), to)
        to = o
        r += tr
    return r

def decrypt(v, k):
 
    """
    DeCrypt Message
    消息解密 
    """
    l = len(v)
    prePlain = decipher(v, k)
    pos = (ord(prePlain[0]) & 0x07L) +2
    r = prePlain
    preCrypt = v[0:8]
    for i in xrange(8, l, 8):
        x = xor(decipher(xor(v[i:i+8], prePlain),k ), preCrypt)
        prePlain = xor(x, preCrypt)
        preCrypt = v[i:i+8]
        r += x
    if r[-7:] != '\0'*7: return None
    return r[pos+1:-7]


