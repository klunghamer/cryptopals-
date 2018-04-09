import binascii
import base64
from itertools import cycle, izip

### Challenge 1
def hexToBase64(hex):
    decoded = hex.decode("hex")
    return decoded.encode("base64")
# hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")


### Challenge 2
def rawToHex(str):
    hex = str.encode("hex")
    return hex

def hexToRaw(bytes):
    raw = bytes.decode("hex")
    return raw

def XOR(str1, str2):
    result = bytearray(len(str1))
    for i in range(len(str1)):
        result[i] = str1[i] ^ str2[i]
    return result

def XORHex(str1, str2):
    str1 = bytearray(hexToRaw(str1))
    str2 = bytearray(hexToRaw(str2))
    result = XOR(str1, str2)
    result = rawToHex(bytes(result))
    return result
# XORHex("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")


### Challenge 3
frequencyTable = {
    'a': 0.0651738,
    'b': 0.0124248,
    'c': 0.0217339,
    'd': 0.0349835,
    'e': 0.1041442,
    'f': 0.0197881,
    'g': 0.0158610,
    'h': 0.0492888,
    'i': 0.0558094,
    'j': 0.0009033,
    'k': 0.0050529,
    'l': 0.0331490,
    'm': 0.0202124,
    'n': 0.0564513,
    'o': 0.0596302,
    'p': 0.0137645,
    'q': 0.0008606,
    'r': 0.0497563,
    's': 0.0515760,
    't': 0.0729357,
    'u': 0.0225134,
    'v': 0.0082903,
    'w': 0.0171272,
    'x': 0.0013692,
    'y': 0.0145984,
    'z': 0.0007836,
    ' ': 0.1918182
}

def score(str):
    total = 0
    for i in str.lower():
        if i in frequencyTable:
            total += frequencyTable[i]
    return total

def singleByteXOR(str):
    max = 0
    for i in range(256):
        testStr = len(str) * [i]
        xored = bytes(XOR(str, testStr))
        totalScore = score(xored)
        if totalScore > max:
            max = totalScore
            final = xored
            char = chr(i)
    return char, final
# print singleByteXOR(bytearray.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))


### Challenge 4
def findSingleByteXOR(file):
    max = 0
    for line in open("input_challenge4.txt", "rb"):
        line = line.strip()
        str = bytearray.fromhex(line)

        for i in range(256):
            testStr = len(str) * [i]
            xored = bytes(XOR(str, testStr))
            totalScore = score(xored)
            if totalScore > max:
                max = totalScore
                final = xored
                char = chr(i)
    return char, final
# print findSingleByteXOR("input_challenge4.txt")


### Challenge 5
def repeatingKeyXOR(str, key):
    repeatedKey = bytearray("ICE" * len(str))
    xoredText = bytes(XOR(bytearray(str), repeatedKey))
    return xoredText.encode("hex")
# print repeatingKeyXOR("Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal", "ICE")


### Challenge 6
def strToBinary(str):
    return ''.join(format(ord(x), '08b') for x in str)

def findHammingDistance(str1, str2):
    i = 0
    count = 0
    x = strToBinary(str1)
    y = strToBinary(str2)
    while i < len(x):
        if x[i] != y[i]:
            count += 1
        i += 1
    return count
# print findHammingDistance("this is a test", "wokka wokka!!!")


def breakRepeatingKeyXOR(file):
    input = base64.b64decode(open(file, 'r').read())
    print input

x = base64.b64decode(open('input_challenge6.txt', 'r').read())
# print x

str1 = x[0:7]
str2 = x[8:15]
# print str1
# print str2

# print findHammingDistance(str1, str2)

def normalizedHammingDistance(input, KEYSIZE):
    sum = 0
    for i in range(len(input)/(KEYSIZE-1)):
        sum = findHammingDistance(input[(i+0)*KEYSIZE:(i+1)*KEYSIZE], input[(i+1)*KEYSIZE:(i+2)*KEYSIZE])
    average = (1.0*sum)/len(input)/(KEYSIZE-1)
    normalized = average/KEYSIZE
    print normalized

    # distance = findHammingDistance(str1, str2)
    # normalized = (distance * 1.0)/len(str1)
    # return normalized

# normalizedHammingDistance("this is a testwokka wokka!!!", 14)
# print 37.0/14
