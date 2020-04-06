#!/usr/bin/python3

###########################################################################
#  Copyright 2019 Supranational LLC
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
###########################################################################

# Comments refer to the paper "Efficient verifiable delay functions" by
# Benjamin Wesolowski, specifically the 2/5/19 eprint update.
# https://eprint.iacr.org/2018/623

import hashlib
import random
import sympy
import json

###########################################################################
# Constants
###########################################################################

# Size of the small prime. For RSA 1024 this would be around 168 bits.
PRIME_BITS = 256
PRIME_BYTES = PRIME_BITS // 8
MOD_BITS = 2048

proof = json.loads(open('proof_0x.json').read())

# 2048 bit RSA modulus - this is fixed for a long time
modulus = int(proof['modulus'])

###########################################################################
# Inputs
###########################################################################

# VDF input taken from Ethereum block hash. This is "g" in the wesolowski
# paper. 
# https://etherscan.io
# eth block 9619000
# We might want to send in a block number and take the block hash from the
# chain if that is an option. 
#g = 83554654396998814025015691931508621990409003355162694699046114859281714059599
g = int(proof['g'])

# Number of iterated squares in the VDF. The VDF computes:
#  y = g**(2**t)
# as described in Algorithm 1. This should be an input since it will
# vary depending on use case. 
t = int(proof['t'])

# Final VDF evaluation result. We probably don't need to send this in -
# verification method 2 does not need it. 
y = int(proof['y'])

# Small prime used to generate the proof. Step 1 in proof generation from
# page 10 in the paper. Note we will look at more EVM efficient ways to
# generate this.
l = int(proof['l'])

# Proof value. Step 2 on page 10 in the Wesolowski paper and Algorithm 1.
pi = int(proof['pi'])

def hash_input(g, y, desired_bits):
  #bytes = "{:x}*{:x}".format(g, y).encode()
  bytes_g = g.to_bytes(PRIME_BITS//8, byteorder='big')
  bytes_y = y.to_bytes(MOD_BITS//8, byteorder='big')
  bytes = bytes_g + bytes_y
  hash = hashlib.sha256(bytes).digest()
  h = int.from_bytes(hash, byteorder='big')

  mask = (1 << desired_bits) - 1
  return h & mask


# Sample a prime from Primes(2k) as described on page 10 of the Wesolowski
# paper. This function is not great for the EVM but there are ideas on
# how to improve it. 
# Sample a prime
#  g - VDF input
#  y - VDF output
def sample_prime(g, y, desired_bits):
  l = None

  mask = (1 << desired_bits) - 1
  bytes_g = g.to_bytes(PRIME_BITS//8, byteorder='big')
  bytes_y = y.to_bytes(MOD_BITS//8, byteorder='big')
  bytes = bytes_g + bytes_y
  #bytes = "{:x}*{:x}".format(g, y).encode()
  hash = hashlib.sha256(bytes).digest()
  l = int.from_bytes(hash, byteorder='big')

  while True:
    # Mask out all but desired number of bits
    l = l & mask
    # Set the top bit
    l = l | (1 << (desired_bits - 1))
  
    if sympy.isprime(l):
      break

    # Number is not prime, increment and try again.
    l += 1

  return(l)

def check_in_group(e):
    return not e > modulus//2

def cast_to_group(e):
    if e > modulus//2:
        return modulus - e
    else:
        return e

# ###########################################################################
# # Proof verification Method 1 - Algorithm 2 in Wesolowski paper
# ###########################################################################

# In this approach we need to send y and pi to the verifier, each of which
# are the RSA modulus size. An optimization is possible (below) where
# we can transmit fewer bits. 

# Compute the sample prime. Since g is already a block hash we are using that
# directly as the input. 
# l = sample_prime(g, y, PRIME_BITS)

# # Compute r per the verification process
r = pow(2, t, l)

# # Verify the result
if (pow(pi, l, modulus) * pow(g, r, modulus) % modulus) != y:
  print("ERROR: proof does not verify")
else:
  print("Method 1 PASS!")
exit()

###########################################################################
# Proof verification Method 2 - reduced storage from section 4.2 from paper
###########################################################################

# In this approach we send l (256 bits) and pi (2048 or 1024 bits) and
# use them to recover y. This is probably the preferred approach. 

if not check_in_group(g):
  print("ERROR: input is not in the quotient group")

if not check_in_group(pi):
  print("ERROR: proof is not in the quotient group")
  
# Compute r and y per the verification process in 4.2
r = cast_to_group(pow(2, t, l))
y = cast_to_group((pow(pi, l, modulus) * pow(g, r, modulus)) % modulus)

if not check_in_group(y):
  print("ERROR: output is not in the quotient group")

# Verify l
mask  = (1 << (PRIME_BITS - 1)) - 1
mask ^= ((1 << 12) - 1)
if l & mask != hash_input(g, y, PRIME_BITS) & mask:
  print("ERROR: l does not match the input hash")
if l >> (PRIME_BITS - 1) == 0:
  print("ERROR: top bit of l is not set")
if not sympy.isprime(l):
  print("ERROR: l is not prime")

validate_l = sample_prime(g, y, PRIME_BITS)
if validate_l != l:
  print("ERROR: proof does not verify - l does not match")
else:
  print("Method 2 PASS!")


