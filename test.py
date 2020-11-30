from RSATools import RSA
import time
import Crypto.PublicKey.RSA

start = time.clock()
RSA.KeyGen()
elapsed = (time.clock() - start)
print("Time used:%d secs",elapsed)
