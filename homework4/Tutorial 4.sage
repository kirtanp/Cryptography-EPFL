#####
#################### Exercises 1, 2, and 5 ##########
#####    

#Bit operations in sage / python

#Convert a string written in hexadecimal into its numerical value
a = int("0b",16) #int("0x0b",16) would work as well
print "a =",a

#Convert a string written in binary into its numerical value
b = int("1011001",2) 
print "b =",b

#Convert an integer back into a hexadecimal string
#The 02 indicates the desired size of the string (for printing leading zeros)
#The integer a should be 0 <= a <= 255
s = "{:02x}".format(a)
print "a in hexa =",s

#Convert an integer back into a binary string
#The 08 indicates the desired size of the string (for printing leading zeros)
#The integer a should be 0 <= a <= 255
s = '{0:08b}'.format(b)
print "a in binary =",s

c1 = int("11",16)
c2 = int("12",16)
print "c1 =", "{:02x}".format(c1)
print "c2 =", "{:02x}".format(c2)
c3 = int("11001100", 2)
c4 = int("10100110", 2)
print "c3 =", '{0:08b}'.format(c3)
print "c4 =", '{0:08b}'.format(c4)
b1 = int("0", 2)
b2 = int("1", 2)
print "b1 =", '{0:b}'.format(b1)
print "b2 =", '{0:b}'.format(b2)

import binascii
c3 = "abcdefghijklmnop"
# Encode ascii as hex string
c3_hex = binascii.b2a_hex(c3) # or c3_hex = c3.encode("hex")
print c3_hex
# Decode from hex string to string
c3 = binascii.a2b_hex(c3_hex) # or  c3 = c3_hex.decode("hex")
print c3

#All the following binary operations work only with Integers
#XOR in sage is ^^
print "c1 XOR c2 =", "{:02b}".format(c1 ^^ c2) ##We do the XOR
print "b1 XOR b2 =", "{0:b}".format(b1 ^^ b2) ##We do the XOR

#AND is &
print "c1 AND c2 =", "{:02x}".format(c1 & c2) ##We do the AND
print "b1 AND b2 =", "{0:b}".format(b1 & b2) ##We do the XOR

#OR is |
print "c1 OR c2 =", "{:02x}".format(c1 | c2) ##We do the OR  
print "b1 OR b2 =", "{0:b}".format(b1 | b2) ##We do the XOR

#XOR of strings, AES and base64

from Crypto.Util import strxor
from Crypto.Cipher import AES

"""
performs the xor of string a and b (every character is treated as an 8-bit value)
"""
def xor(a,b):
    return strxor.strxor(a,b)

    
#AES encryption of message <m> with ECB mode under key <key>
def aes_encrypt(message, key):
    obj = AES.new(key, AES.MODE_ECB,'')
    return obj.encrypt(message)
    
#AES decryption of message <m> with ECB mode under key <key>
def aes_decrypt(message, key):
    obj = AES.new(key, AES.MODE_ECB,'')
    return obj.decrypt(message)

message = "abcdefghijklmnop"
key = "aabbaabbaabbaabb"
ciphertext = aes_encrypt(message, key)

hex_ciphertext = ciphertext.encode("hex")

print "If we try to print the ciphertext there are many unprintable characters:", ciphertext

print "So we print it in hexadecimal:", hex_ciphertext

#We get back the ciphertext 
ciphertext = hex_ciphertext.decode("hex")

plaintext = aes_decrypt(ciphertext, key)
print "the plaintext is:", plaintext


####
####Exercises 1 and 3 #########################
####
"""
Connection to a server <server_name> with port <port> and send message <message> (has to end with '\n')
"""

import sys
import socket

def connect_server(server_name, port, message):
    server = (server_name, int(port)) #calling int is required when using Sage
    s = socket.create_connection(server)
    s.send(message)
    response=''
    while True: #data might come in several packets, need to wait for all of it
        data = s.recv(9000)
        if not data: break
        response = response+data
    s.close()
    return response


####
#### Exercise 4 ######################
####

#Elliptic curves in Sage
#Creation of an elliptic curve with equation y^2 = x^3 + ax + b over a finite field F = GF(p)
#Command is EllipticCurve(F,[a,b])

#As an example we create the Elliptic curve with equation y^2 = x^3 + 3x + 1 over GF(29)

#First we create the finite field
F = GF(29)
#Then we create the Elliptic curve E
E = EllipticCurve(F, [3,1])
print E

#To check whether a point (x,y) is on the curve, call E.is_on_curve(x,y)
print "is the point (1,2) on the curve?",  E.is_on_curve(1,2)
print "is the point (26,20) on the curve?",  E.is_on_curve(26,20)

#To create a point P with coordinates (x,y) on E, simply call E(x,y)
P = E(26,20)
#To print a point P call P.xy()
print "The coordinates of P are", P.xy()

#To add two points P,Q call + operator
Q = E(1,11)
print "Q =", Q.xy()
print "P+Q =", (P+Q).xy()

#To multiply a point P by a constant l, call l*P
print "5Q =", (5*Q).xy()

#To obtain the point at infinity call E(0)
O = E(0)
print "Point at infinity O =", O #Not possible to call for x,y coordinates!
#To check whether a point is the point at infinity, call is_zero() function
print "Is point Q the point at infinity? ", Q.is_zero()
print "Is point O the point at infinity? ", O.is_zero()

#Compute the order of the curve. WARNING CAN BE SLOW
print "The order of E is",E.order()

#Given a x coordinate, it's possible to list all points on the curve that have this x coordinate with the function lift_x and the parameter all=True
print "The possible points (in projective form) when x = 26 are",  E.lift_x(26, all=True)
print "The possible points (in xy() form) when x = 26 are",  map(lambda u: u.xy(),E.lift_x(26, all=True))

