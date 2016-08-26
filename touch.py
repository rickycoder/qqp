#coding:utf-8

import sys
import socket
from Crypt import encrypt,decrypt
from binascii import b2a_hex, a2b_hex
from random import randint

#qq的udp服务地址
address = ('sz2.tencent.com', 8000)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#touch包的各个部分
qq_num = "%06x" % 3449116614
pack_start = "02"
pack_version = "3103"
cmd_num = "0825"
pack_seq_num = "%02x" %  randint(1,65535)
pack_pad_str = "03000000010101000064ED00000000"
team_key = "C3B6C0FBCA4698AD09B699E0BD6F728A"

#touch pack body
pack_body = "001800160001000004160000000100001327" + qq_num + "000000000114001D0102001902EE875A9FC9E61DDD794D47CF27D4EC85FE07742E7C01851E"
pack_body = b2a_hex(encrypt(a2b_hex(pack_body),a2b_hex(team_key)))

#touch pack end
pack_end = "03"

#构造touch数据包
data = pack_start + pack_version + cmd_num + pack_seq_num + qq_num + pack_pad_str + team_key + pack_body + pack_end
 
#将可见的16进制的ascii形式转换成真实的16进制数据
data = a2b_hex(data)

#发送touch数据包给qq的udp服务器 
s.sendto(data, address)

#获取返回数据
touch_rep_pack = s.recv(1024)

#重返回的数据包中截取head和body部分
rep_pack_head = touch_rep_pack[0:14]
rep_pack_body = touch_rep_pack[14:-1]

#rep数据包的body部分是用key进行tea加密了，如果要查看需要解密
print b2a_hex(rep_pack_head) + b2a_hex(decrypt(rep_pack_body,a2b_hex(team_key)))


data="FC59E5335FACF6C4B8B797D457367E684A0844C20EA3ED84795A401654582DF3E2610AE55E4DD8FD0B73493F509C7072E92FCC6C74861F338432B43724AA3AFC4B1F4F726FA474A6ED3F03A876E35066C4D42A0F1EB7512C89A0CEAF60231C3F08D5D411FFE93E2F1ABEE1D0ADE4DDBBB23AD8B28902B9057F0007E93A333B5C70E838A601889B1B"
print "======================="
print b2a_hex(decrypt(a2b_hex(data),a2b_hex("8EC631AB3FEE52C3C726733A0D90C8C8")))

