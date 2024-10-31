## This script is used modified from https://github.com/Phildo/ethbrute/blob/master/brute.py

from multikdf.scrypt import scrypt_kdf
#import hashlib
import sha3
import json
import math

import argparse, sys

parser=argparse.ArgumentParser()

parser.add_argument("-w", help="Wallet file, example: -w wallet.json")
parser.add_argument("-p", help="Password file list, example: -p rockyou-60.txt")

args=parser.parse_args()

if args.w == None or args.p == None:
    print(parser.format_help())
    sys.exit()

wallet = args.w
passwords = args.p

with open(wallet) as wallet_file:
  wallet = json.load(wallet_file)

dklen = 32
salt = bytearray.fromhex(wallet["crypto"]["kdfparams"]["salt"])
r = wallet["crypto"]["kdfparams"]["r"]
p = wallet["crypto"]["kdfparams"]["p"]
n = wallet["crypto"]["kdfparams"]["n"]
#262144 #NOTE- put Log BASE2 n here. so, if n = 262144 in the .json wallet file, put 18 here
if(n == 262144):
    n_log2 = 18
else:
    n_log2 = int(math.log2(n))
    print(f"Converting n from {n} to log2(n) = {n_log2}")
ciphertext = bytearray.fromhex(wallet["crypto"]["ciphertext"])
mac = bytearray.fromhex(wallet["crypto"]["mac"])

file = open(passwords, "r")
for line in file:
    password = line.strip('\n')
    print ("trying "+password)

    derived_key = scrypt_kdf(password, salt, r, p, n_log2, dklen)[16:32]
    concat = derived_key + ciphertext

    k = sha3.keccak_256()
    k.update(concat)
    hashconcat = bytearray.fromhex(k.hexdigest())

    if hashconcat == mac:
        print (password + " WORKED!")
        exit()
