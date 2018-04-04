import binascii
import base64
import string
from Crypto.Util.strxor import strxor_c

### Challenge 1
def hexToBase64(hex):
    decoded = binascii.unhexlify(hex)
    return base64.b64encode(decoded).decode('ascii')
    # print base64.b64encode(decoded).decode('ascii')
# hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")


### Challenge 2
def toHex(str):
    hex = str.encode("hex")
    return hex
    # print hex

def hexToRaw(str):
    raw = str.decode("hex")
    return raw

def XORHex(str1, str2):
    str1 = hexToRaw(str1)
    str2 = hexToRaw(str2)
    result = ''

    for x,y in zip(str1,str2):
        result += chr(ord(x) ^ ord(y))
    return toHex(result)
# XORHex("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")


### Challenge 3

freqs = {
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

def score(s):
    score = 0
    for i in s:
        c = i.lower()
        if c in freqs:
            score += freqs[c]
    return score


def string_xor(s, c):
     c = ord(c)  # dirty dynamic typing
     return ''.join(map(lambda h: chr(ord(h) ^ c), s))


def singleByeteXOR(str):
    str = binascii.unhexlify(str)
    results = []
    for letter in string.ascii_letters:
        result = string_xor(s, letter)
        results.append(result)
    max = score(results[1])
    final = 1
    for i in results:
        if score(i) > max:
            max = score(i)
            final = i
    return final
    # print final

# singleByeteXOR("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")


### Challenge 4
