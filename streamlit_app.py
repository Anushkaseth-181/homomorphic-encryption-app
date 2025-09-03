

import streamlit as st
import numpy as np
from Pyfhel import Pyfhel
from phe import paillier
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# ======================
# BFV setup
# ======================
HE_BFV = Pyfhel()
HE_BFV.contextGen(scheme='BFV', n=2**14, t=65537)
HE_BFV.keyGen()

# ======================
# CKKS setup
# ======================
HE_CKKS = Pyfhel()
HE_CKKS.contextGen(scheme='CKKS', n=2**14, scale=2**30, qi_sizes=[60,30,30,30,60])
HE_CKKS.keyGen()

# ======================
# Paillier setup
# ======================
paillier_pubkey, paillier_privkey = paillier.generate_paillier_keypair()

# ======================
# RSA setup
# ======================
rsa_key = RSA.generate(2048)
rsa_pubkey = rsa_key.publickey()
rsa_cipher = PKCS1_OAEP.new(rsa_pubkey)
rsa_decipher = PKCS1_OAEP.new(rsa_key)

# ======================
# Streamlit UI
# ======================
st.title("Homomorphic Encryption Calculator")
a = st.number_input("Enter number a:", value=5.0)
b = st.number_input("Enter number b:", value=3.0)

# ======================
# BFV operations
# ======================
a_int, b_int = int(a), int(b)
cA_bfv = HE_BFV.encryptInt(np.array([a_int], dtype=np.int64))
cB_bfv = HE_BFV.encryptInt(np.array([b_int], dtype=np.int64))
bfv_sum = HE_BFV.decryptInt(cA_bfv + cB_bfv)[0]
bfv_sub = HE_BFV.decryptInt(cA_bfv - cB_bfv)[0]
bfv_mul = HE_BFV.decryptInt(cA_bfv * cB_bfv)[0]

st.header("BFV (Integer)")
st.write(f"Sum: {bfv_sum}, Sub: {bfv_sub}, Mul: {bfv_mul}")

# ======================
# CKKS operations
# ======================
cA_ckks = HE_CKKS.encryptFrac(np.array([a], dtype=np.float64))
cB_ckks = HE_CKKS.encryptFrac(np.array([b], dtype=np.float64))
ckks_sum = HE_CKKS.decryptFrac(cA_ckks + cB_ckks)[0]
ckks_sub = HE_CKKS.decryptFrac(cA_ckks - cB_ckks)[0]
ckks_mul = HE_CKKS.decryptFrac(cA_ckks * cB_ckks)[0]

st.header("CKKS (Float)")
st.write(f"Sum: {ckks_sum}, Sub: {ckks_sub}, Mul: {ckks_mul}")

# ======================
# Paillier operations (Additive Homomorphism)
# ======================
cA_pail = paillier_pubkey.encrypt(a_int)
cB_pail = paillier_pubkey.encrypt(b_int)
paillier_sum = paillier_privkey.decrypt(cA_pail + cB_pail)

st.header("Paillier (Additive Homomorphism)")
st.write(f"Sum: {paillier_sum}")
st.write("Subtraction and multiplication not supported for Paillier")

# ======================
# RSA operations (No homomorphism, just encryption/decryption)
# ======================
enc_a_rsa = rsa_cipher.encrypt(str(a).encode())
enc_b_rsa = rsa_cipher.encrypt(str(b).encode())
dec_a_rsa = float(rsa_decipher.decrypt(enc_a_rsa).decode())
dec_b_rsa = float(rsa_decipher.decrypt(enc_b_rsa).decode())

st.header("RSA (Standard Public-Key)")
st.write(f"Encrypted a: {enc_a_rsa[:20]}... (truncated)")
st.write(f"Encrypted b: {enc_b_rsa[:20]}... (truncated)")
st.write(f"Decrypted a: {dec_a_rsa}, Decrypted b: {dec_b_rsa}")
st.write("RSA is not homomorphic, so no direct sum/mul on ciphertexts")
