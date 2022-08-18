## I. Backgrouds
### - Current TLS & KTLS
- Handshake in Userspace
- Data Enryption & Decryption in Kernel
### - Kernel TLS 1.3 HS needed by
- QUIC: https://datatracker.ietf.org/doc/html/rfc9001
- NFSv4: https://datatracker.ietf.org/doc/draft-ietf-nfsv4-rpc-tls/
### - TLS handshake (1.3)
- Certificate Chain (with certificate request)
```
          ClientHello
          + key_share               -------->
                                                    HelloRetryRequest
                                    <--------             + key_share
          ClientHello
          + key_share               -------->
                                                          ServerHello
                                                          + key_share
                                                {EncryptedExtensions}
                                                {CertificateRequest*}
                                                       {Certificate*}
                                                 {CertificateVerify*}
                                                           {Finished}
                                    <--------     [Application Data*]
          {Certificate*}
          {CertificateVerify*}
          {Finished}                -------->
                                    <--------      [NewSessionTicket]
          [Application Data]        <------->      [Application Data]
```
- PSK (with early data)
```
         ClientHello
         + early_data
         + key_share*
         + psk_key_exchange_modes
         + pre_shared_key
         (Application Data*)     -------->
                                                         ServerHello
                                                    + pre_shared_key
                                                        + key_share*
                                               {EncryptedExtensions}
                                                       + early_data*
                                                          {Finished}
                                 <--------       [Application Data*]
         (EndOfEarlyData)
         {Finished}              -------->
         [Application Data]      <------->        [Application Data]

     (): encrypted with early key
     {}: encrypted with handshake key
     []: encrypted with application key
```
## II. TLS_HS
### - Files in kernel
```
- inclue/crypto/tls_hs.h
- crypto/tls_hs.c
  (build with CONFIG_CRYPTO_TLS_HS=m/y)
```

### - APIs
```
  TLS_HS (see APIs.a)
    |-- TLS_HS_GEN (see APIs.b)
    |      |
    |      |---- TLS_HS_TCP (see III)
    |      |---- NFS (see III)
    |
    |-- QUIC (see III)
```
#### a. TLS_HS (msg):
- Core:
    1. tls = tls_handshake_create(is_serv)
    2. **state = tls_handshake(tls, msg)**
    ```
    - msg:
      input:  a tls 1.3 msg to process
      output: a tls msg to reply
      (note: when input is NULL, output is tls 1.3 client/server hello msg.)
    - state:
      TLS_ST_START
      TLS_ST_RCVD
      TLS_ST_WAIT
      TLS_ST_CONNECTED
      (see State Transition)
    ```
    3. tls_handshake_get/set(tls, type, vec)
    ```
    - type/opt:
      TLS_T_PKEY: private key
      TLS_T_PSK:
      TLS_T_CA:
      TLS_T_CRT_REQ: client certificate request
      TLS_T_CRT: certificate chain
      TLS_T_EXT: unknow extension
      TLS_T_EARLY: flag for early data send and recv
    ```
    4. tls_handshake_post(tls, type, msg)
    5. tls_handshake_destroy(tls)
 - Extra:
    1. tls_secret_get(tls, level, srt)
    2. tls_hkdf_expand(tls, srt, hash, label, key)
    3. tls_hkdf_extract(tls, srt, hash, key)
    ```
    - level:
      TLS_SE_RMS: resumption secret
      TLS_SE_EA: early secret
      TLS_SE_HS: handshake secret
      TLS_SE_AP: master secret
    ```
#### b. TLS_HS_GEN (sk):
- Core:
    1. **tls = tls_sk_handshake(sk, data, keyring, flag)**
    ```
    - sk:
      input:  a TCP established socket
      output: a kTLS socket with keys set
    - data:
      early data to send and early data recevied
    - keyring:
      set for reading keys from userspace, or keys should be set in
      kernel users by tls_handshake_set(...).
    - flag:
      TLS_F_SERV: make it work as a server
      TLS_F_PSK
      TLS_F_CRT
      TLS_F_CRT_REQ
      TLS_F_NO_KTLS:
        without KTLS, users can use tls_ap_de/encrypt() to send/recv app data.
    - tls:
      the obj returned, users can either hold it for future post handshake msg
      processing or destroy it.
    ```
    2. tls_sk_handshake_post(sk, tls, type, msg)
 - Extra:
    1. tls_ap_encrypt(tls, data, seq)
    2. tls_ap_decrypt(tls, data, seq)

### - State Transition
State Transition is simplied in kernel implementation:
```
    Client                                   Server

    TLS_ST_START                          TLS_ST_START
                           CH
                     ------------->
    ---------------------------------------------------
                           SH
                     <-------------
    TLS_ST_RCVD                            TLS_ST_RCVD
                           EE
                     <-------------
    TLS_ST_WAIT            CRT
                           ...
                           FIN
                     <-------------
                                           TLS_ST_WAIT
    ---------------------------------------------------
                           CRT
                           ...
                           FIN
                     ------------->
    TLS_ST_CONNECTED                  TLS_ST_CONNECTED
```

### - Features
#### a. ciphers & algorithms:
  - HKDF extract/expand: hmac(sha256)
  - Header Protection: ecb(aes)
  - ECDH key exchange: secp256r1(0x0017)
  - Certificate: rsa_pkcs1_sha256(0x0401)/rsa_pss_rsae_sha256(0x0804)
  - Signature Algorithm: rsa_pss_rsae_sha256(0x0804)
  - AEAD: TLS_AES_128_GCM_SHA256(0x1301)
#### b. functions:
  - Certificate Chain and CA on Both Sides
  - PSK
  - Session Resumption
  - Early Data
  - Hello Retry Request on Server
#### c. msgs & exts:
```
  TLS_MT_HELLO_RETRY_REQUEST      0
  TLS_MT_CLIENT_HELLO             1
  TLS_MT_SERVER_HELLO             2
  TLS_MT_NEWSESSION_TICKET        4
  TLS_MT_END_OF_EARLY_DATA        5
  TLS_MT_ENCRYPTED_EXTENSIONS     8
  TLS_MT_CERTIFICATE              11
  TLS_MT_CERTIFICATE_REQUEST      13
  TLS_MT_CERTIFICATE_VERIFY       15
  TLS_MT_FINISHED                 20
  TLS_MT_KEY_UPDATE               24
```
```
  TLS_EXT_server_name             0
  TLS_EXT_supported_groups        10
  TLS_EXT_ec_point_formats        11
  TLS_EXT_signature_algorithms    13
  TLS_EXT_heartbeat               15
  TLS_EXT_alpn                    16
  TLS_EXT_signed_cert_timestamp   18
  TLS_EXT_padding                 21
  TLS_EXT_encrypt_then_mac        22
  TLS_EXT_extended_master_srt     23
  TLS_EXT_session_ticket          35
  TLS_EXT_psk                     41
  TLS_EXT_early_data              42
  TLS_EXT_supported_versions      43
  TLS_EXT_cookie                  44
  TLS_EXT_psk_kex_modes           45
  TLS_EXT_certificate_authorities 47
  TLS_EXT_post_handshake_auth     49
  TLS_EXT_signature_algs_cert     50
  TLS_EXT_key_share               51
```

Note:

1. TLS_MT_HELLO_RETRY_REQUEST can be sent on server, but on client it will
   abort when receiving this msg, as "ciphers & algorithms" supported are
   very simple.

2. TLS_MT_END_OF_EARLY_DATA is not processed by TLS_HS, and TLS_HS only
   sets 'early' flag when receiving TLS_EXT_early_data, and other things
   are left to users to implement, like what it does in TLS_HS_GEN. QUIC
   doesn't even use this msg .

## III. Usage:
### - QUIC
#### kernel space patch:

- commit: https://github.com/lxin/tls_hs/commit/6293a5c836d0cbcef9a54e907cde0bffefefa852
- usage: https://github.com/lxin/tls_hs/blob/quic/net/quic/frame.c#L654

#### userspace program:

- https://github.com/lxin/tls_hs-tests#ii-quic

### - TCP
#### kernel space patch:

- https://github.com/lxin/tls_hs/commit/f9e59ec5927ba86dc266f2bf789e66be05f1b085

#### userspace program:

- https://github.com/lxin/tls_hs-tests#i-tls_hs_tcp

### - NFS
#### kernel space patch:

- https://github.com/lxin/tls_hs/commit/40d30effb6b12dea53ff90caeb5e5b7940e7932d

#### userspace program:

- https://github.com/lxin/tls_hs-tests#iii-nfs

### V. Tests
```
+-----------------------------------------------------------------------+
|               | Kc -> Ks      | Uc -> Ks      | Kc -> Us      |       |
+-----------------------------------------------------------------------+
| CRT           | Q & N         | Q & N         | Q & N         | DONE  |
+----------------------------------------------------------------       |
| CRTs          | Q & N         | Q & N         | Q & N         | FOR   |
+----------------------------------------------------------------       |
| CRT_REQ       | Q & N         | Q & N         | Q & N         | QUIC  |
+----------------------------------------------------------------  &    |
| CRTs_REQ      | Q & N         | Q & N         | Q & N         | NFS   |
+-----------------------------------------------------------------------+
| PSK           | Q & N         | Q & N         | Q & N         | TODO  |
+---------------------------------------------------------------- For   |
| PSK_0RTT      | Q & N         | Q & N         | Q & N         | NFS   |
+-----------------------------------------------------------------------+
| SES           | Q             | Q             | Q             |       |
+----------------------------------------------------------------       |
| SES_0RTT      | Q             | Q             | Q             | QUIC  |
+---------------------------------------------------------------- only  |
| KU            | Q             | Q             | Q             |       |
+-----------------------------------------------------------------------+

U: userspace openssl
K: kernelspace tls_hs
c: client
s: server
Q: QUIC
N: NFS
```
