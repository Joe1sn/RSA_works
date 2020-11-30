# RSA_works
RSA 小组（个人）作业
使用python3
<font color = red>由于生成私钥的格式为</font>

```
-----BEGIN PRIVATE KEY-----
................................
-----END PRIVATE KEY-----
```

为了后续支持其他协议

这里需要手动添加为

```
-----BEGIN RSA PRIVATE KEY-----
................................
-----END RSA PRIVATE KEY-----
```

## RSAtools.py
- 实现rsa得主要算法文件
- 调用pycryptodome库实现ssh的证书生成

## test.py
使用前请安装pycryptodome库

测试文件
