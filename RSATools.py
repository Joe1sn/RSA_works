import binascii
import struct
import Crypto.PublicKey.RSA
import sys


from Crypto.IO import PEM
from Crypto.IO import PKCS8
from random import randint
from Crypto.Util.number import inverse
from Crypto.Math.Numbers import Integer
from Crypto import Random
from Crypto.Util.py3compat import tobytes, bord, tostr
from Crypto.Util.asn1 import DerSequence
from Crypto.Math.Numbers import Integer
from Crypto.Math.Primality import (test_probable_prime,
								   generate_probable_prime, COMPOSITE)
from Crypto.PublicKey import (_expand_subject_public_key_info,
							  _create_subject_public_key_info,
							  _extract_subject_public_key_info)

from Crypto.Util.py3compat import tobytes, is_native_int
from Crypto.Util._raw_api import (backend, load_lib,
                                  get_raw_buffer, get_c_string,
                                  null_pointer, create_string_buffer,
                                  c_ulong, c_size_t)
# from ._IntegerBase import IntegerBase


# from Cryptodome.PublicKey import RSA
# from Cryptodome.Cipher import PKCS1_v1_5

class FileGen(object):
	"""docstring for PKCSFile"""
	def __init__(self, arg):
		super(PKCSFile, self).__init__()
		self.arg = arg





class RSA(object):
	"""docstring for RSA"""
	def __init__(self, arg):
		super(RSA, self).__init__()
		self.arg = arg

#模重复平方
	def ReModule(b,n,m): #b^n(mod m)
	#1-二进制转换n
		result=1
		n1=bin(n)
		BinList = list(str(n1)[2:][::-1])
		#开始遍历
		for i in BinList:
			if int(i) == 1:
				result = (result*b)%m
				b = (b*b)%m
			else:
				b = (b*b)%m
		return result

#大素数生成
	def PrimerGen(size): #生成size位的素数,rsa2048中size=2048
		while True:
			n = randint(0, 1 << (size))#求2^size之间的大数
			if n % 2 != 0:
				found = True
				# 随机性测试
				for i in range(0, 2):   #5的时候错误率已经小于千分之一
					if RSA.PrimerCheck(n) == False:
						found = False
						break
				if found == True:
					return n

#Miller Rabin素性检测
#费马小定理+二次探测
	def PrimerCheck(num,times=3): #对num检测times次
		if num < 3:
			return num==2
		u = num-1
		t = 0
		while u%2 ==0:#若为偶数
			u//=2
			t+=1
		for i in range(1,times+1): #费马小定理检测
			x = randint(2,num-1)
			v = RSA.ReModule(x,u,num)
			if v==1 or v==num-1:
				continue
			for j in range(t+1):
				v = v*v%num
				if v==num-1:
					break
			else:
				return False
		return True


#欧几里得算法
	def gcd(a, b):
		while a != 0:
			a, b = b % a, a
		return b
#拓展欧几里得
	def inverse(value,modulus):
		modulus = int(modulus)
		if modulus == 0:
			raise ZeroDivisionError("Modulus cannot be zero")
		if modulus < 0:
			raise ValueError("Modulus cannot be negative")
		r_p, r_n = value, modulus
		s_p, s_n = 1, 0
		while r_n > 0:
			q = r_p // r_n
			r_p, r_n = r_n, r_p - q * r_n
			s_p, s_n = s_n, s_p - q * s_n
		if r_p != 1:
			raise ValueError("No inverse value can be computed" + str(r_p))
		while s_p < 0:
			s_p += modulus
		value = s_p

#欧拉定理求公钥
	def Euler(a,n): #a^{\phi(n)}−1
		if a%n==0:
			print(str(a)+"%"+str(n)+"==0")
			return False
		phi_n = 0
		for i in range(1,n):
			if RSA.gcd(i,n)!=0:
				phi_n+=1
		return pow(a,phi_n)-1 #目标是rsa2048 
					#在python pow()已经够用了

#文件格式
	def export_key(e,d,p,q,n,format='PEM', passphrase=None, pkcs=1,
				   protection=None, randfunc=None):
		if format=="OpenSSH":
			e_bytes, n_bytes = [x.to_bytes() for x in (Integer(e), Integer(n))]
			# for x in (e,n):
			# e_bytes = e.to_bytes()
			# n_bytes = n.to_bytes()
			if bord(e_bytes[0]) & 0x80:
				e_bytes = b'\x00' + e_bytes
			if bord(n_bytes[0]) & 0x80:
				n_bytes = b'\x00' + n_bytes
			keyparts = [b'ssh-rsa', e_bytes, n_bytes]
			keystring = b''.join([struct.pack(">I", len(kp)) + kp for kp in keyparts])
			return b'ssh-rsa ' + binascii.b2a_base64(keystring)[:-1]

		if format == "PEM":
			oid = "1.2.840.113549.1.1.1"
			binary_key = DerSequence([0,n,e,d,p,q,d % (p-1),d % (q-1),Integer(q).inverse(p)]).encode()

			key_type = 'PRIVATE KEY'
			pem_str = PEM.encode(binary_key, key_type, passphrase, randfunc)
			binary_key = PKCS8.wrap(binary_key, oid, None)
			return tobytes(pem_str)
		raise ValueError("Unknown key format '%s'. Cannot export the RSA key." % format)

	def KeyGen(filename_pub="id_pub",filename="id_rsa"):
		print("[*]Start")
		p = 0
		q = 0
		while len(str(p)) != 309  or len(str(q)) != 309 or len(str(p*q)) != 617:
			p = RSA.PrimerGen(1024)
			q = RSA.PrimerGen(1024)
			while q==p:
				q = RSA.PrimerGen(1024)

		while q==p:
			q = RSA.PrimerGen(1024)

		if p > q:
			p, q = q, p
		u = inverse(p,q)

		print("[*]p--done")
		print("[*]q--done")
		n = p*q
		print("[*]n---done")

		phi = (p-1)*(q-1)
		print("[*]phi--done")

		e=65537
		print("[*]e--done")

		ed = 1
		while 1:
			if (ed*phi+1)%e==0:
				d = (ed*phi+1)//e
				break
			ed+=1

		print("[*]d--done")

		with open(filename,"wb") as file:
			a = RSA.export_key(e,d,p,q,n,"PEM")
			start = a[0:10]
			mid = a[11:-17]
			last = a[-16:-1]
			string = start+b" RSA "+mid+b" RSA "+last+b"-"
			file.write(string)
			a = 0
			start = 0
			mid = 0
			last = 0
			string = 0
		print("[*]Private Key file is writing in ",filename)

		a=0
		with open(filename_pub,"wb") as file:
			a = RSA.export_key(e,d,p,q,n,"OpenSSH")
			file.write(a)
		a=0
		print("[*]Public Key file is writing in",filename_pub)

		# 检测部分
		cipher = RSA.ReModule(13,e,n)
		m = RSA.ReModule(cipher,d,n)
		if m == 13:
			print("OK")
		else:
			print("false",cipher,m)

		return e,d
