# TLS 1.3 Handshake in Linux Kernel
## The Backgrounds:

  Currently kTLS does Data Encryption and Decryption in Kernel space and TLS
  lib like openssl does Handshake in User space. But Recently there are some
  requirements for TLS Handshake in Kernel, like in these articles:

    https://lwn.net/Articles/892216/
    https://lwn.net/Articles/896746/

  Kernel TLS 1.3 Handshakes are also required by NFSv4 and QUIC in Kernel:

    - QUIC: https://datatracker.ietf.org/doc/html/rfc9001
    - NFSv4: https://datatracker.ietf.org/doc/draft-ietf-nfsv4-rpc-tls/

  This patch series is to add a couple of APIs in crypto to help kernel
  developers complete TLS 1.3 handshake and even process post handshake
  messages. Since the usage doesn't require full support for all TLS'
  version handshake, this implementation is a simplified version with
  those main features supported and for TLS 1.3 only, which saves us a
  lot of work.

  RSASSA-PSS signature (https://lwn.net/Articles/853572/) from Varad Gautam
  is needed, as TLS 1.3 Handshake requires this signature algorithm.

  **Note that**:

  This implementation is not yet ready due to some security flaws in kernel
  crypto APIs according to other developers from security team, see "The
  Security Issue" part.

  Also some people may argue that TLS handshake should stay in user space
  and use up-call to user space in kernel to complete the handshake. That
  is indeed another way to work around this.

  I believe both ways have their own advantages. Here I just post the way
  I tried with TLS HS kernel implementation so that other people will not
  need to start from the beginning when trying this out, and know what we
  can do so far and what we need to do for the existent issues about the
  TLS Handshake implementation in Linux Kernel.

## The APIs & Usage:

  There are 2 levels APIs provided: the 1st one is TLS_HS, and it's in the
  lower level dealing with TLS messages; the 2nd one is TLS_HS_GEN, whose
  input and output are sockets. TLS_HS_GEN is built over TLS_HS.

      TLS_HS (msg)
          |-- TLS_HS_GEN (sk)
          |      |
          |      |---- NFSv4
          |
          |-- QUIC

  QUIC is using TLS_HS while NFS is using TLS_HS_GEN. These new APIs are
  all tested by interacting with openssl and ngtcp2, see more tests in:
  https://github.com/lxin/tls_hs-tests.

### 1. TLS_HS APIs:

  These 4 core APIs are necessary: create an object 'tls' by
  tls_handshake_create(), and configure ca, certs, psks, pkey etc, by
  tls_handshake_get/set(), then generate or process TLS msg by using
  this most important API tls_handshake(), at last destroy it by
  tls_handshake_destroy().

    - tls = tls_handshake_create(is_serv)
    - tls_handshake_get/set(tls, opt, vec)
    - state = tls_handshake(tls, msg)
      * msg:
        input:  a tls 1.3 msg to process.
        output: a tls msg to send for reply.
        (when input is NULL, output is tls 1.3 CH/EE msg)
      * state:
        TLS_ST_START/RCVD/WAIT/CONNECTED: see State Transition
        < 0: error
    - tls_handshake_destroy(tls)

  There are also 4 extra APIs that can be used during or after handshake,
  process post handshake msgs like KeyUpdate, NewSessionTicket etc, by
  tls_handshake_post(). Get different level of secrets by tls_secret_get(),
  then derive keys by tls_hkdf_expand/extract().

    - tls_handshake_post(tls, type, msg)
    - tls_secret_get(tls, level, srt)
      * level:
        TLS_SE_RMS: resumption secret.
        TLS_SE_EA: early secret.
        TLS_SE_HS: handshake secret.
        TLS_SE_AP: master secret.
    - tls_hkdf_expand(tls, srt, h, l, k)
    - tls_hkdf_extract(tls, srt, h, k)

###  2. QUIC usage:

  The following code is from a QUIC implementation based on this lib in:
  https://github.com/lxin/tls_hs/tree/quic, it's used to processing the
  crypto frame, and an good example to show how TLS_HS can be used in a
  lower level handshake, what should be done in different states.

    ret = tls_handshake(qs->tls, tls_vec(&msg, p, hs_len));
    switch (ret) {
    case TLS_ST_START:
    case TLS_ST_WAIT:
        break;
    case TLS_ST_RCVD:
        if (qs->crypt.is_serv) {
            quic_crypto_early_keys_install(qs);

            quic_frame_create(qs, msg, QUIC_FRAME_CRYPTO);
            qs->state = QUIC_CS_SERVER_WAIT_HANDSHAKE;
            quic_crypto_handshake_keys_install(qs);

            tls_handshake(qs->tls, tls_vec(&msg, NULL, 0));
            quic_frame_create(qs, msg, QUIC_FRAME_CRYPTO);
            quic_crypto_application_keys_install(qs);
        } else {
            qs->state = QUIC_CS_CLIENT_WAIT_HANDSHAKE;
            quic_crypto_handshake_keys_install(qs);
        }
        break;
    case TLS_ST_CONNECTED:
        if (qs->crypt.is_serv) {
            qs->state = QUIC_CS_SERVER_POST_HANDSHAKE;
        } else {
            quic_frame_create(qs, msg, QUIC_FRAME_CRYPTO);
            quic_crypto_application_keys_install(qs);
            qs->state = QUIC_CS_CLIENT_POST_HANDSHAKE;
        }
        inet_sk_set_state(sk, QUIC_SS_ESTABLISHED);
        break;
    default:
        err = ret;
    }

see more code in:
https://github.com/lxin/tls_hs/tree/quic
and testing in
https://github.com/lxin/tls_hs-tests#ii-quic

### 3. TLS_HS_GEN APIs:

  This core API works at a higher level and does a general TLS 1.3 handshake
  with a TCP socket, which will become a kTLS socket after. The configuration
  can be done from userspace by setting up a keyring, like "nfs", then in
  user space, add keys by keyctl under "nfs-1":

    # keyctl newring nfs-1 @u

    # keyctl add user psk-0-id "13aa" %:nfs-1
    # keyctl add user psk-0-master \
       `echo 5ac851e04710692cdb8da27668839d60 | xxd -r -p` %:nfs-1
    (PSK)

    # keyctl padd user pkey %:nfs-1 < ./crts/ServerKey.der
    # keyctl padd user crt-0 %:nfs-1 < ./crts/ServerCA.der
    # keyctl padd user crt-1 %:nfs-1 < ./crts/IntermediateCA.der
    # keyctl padd user ca %:nfs-1 < ./crts/RootCA.der
    (Certificates)

  tls_sk_handshake() only needs to be called once to complete the handshake.

    - tls = tls_sk_handshake(sk, data, keyring, flag)
      * sk:
        input:  a TCP established socket.
        output: a kTLS socket with keys set.
      * data:
        early data to send and early data received.
      * keyring:
        set for reading keys/crts from userspace, and left none if the keys/crts
        are set by kernel users via tls_handshake_set(...).
      * flag:
        TLS_F_SERV: works as a server.
        TLS_F_PSK/CRT/CRT_REQ.
        TLS_F_NO_KTLS: w/o kTLS, use tls_ap_de/encrypt() to send/recv app data.

  After it returns tls from tls_sk_handshake, with tls object post handshake
  msgs can be processed with tls_sk_handshake_post(), otherwise, this 'tls'
  object can be destroyed. As it says in TLS_F_NO_KTLS, without kTLS used,
  these 2 APIs tls_ap_en/decrypt() can be used to encrypt and decrypt msgs
  from the original TCP sockets.

    - tls_sk_handshake_post(sk, tls, type, msg)
    - tls_ap_encrypt(tls, data, seq)
    - tls_ap_decrypt(tls, data, seq)

### 4. NFS usage:

  The following code is based on interface xs_tls_connect() added by Chuck
  in his repo, it clearly shows how simply TLS_HS_GEN can be used to complete
  this higher level TLS 1.3 handshake and returns a kTLS sock in kernel. This
  'tls' object can even be destroyed, if there will be no post handshake msgs
  to handle:

    if (transport->xprt.xprtsec == RPC_XPRTSEC_TLS_PSK)
        flag |= TLS_F_PSK;

    tls = tls_sk_handshake(transport->sock, &v, "nfs", flag);
    if (IS_ERR(tls))
        return PTR_ERR(tls);

    tls_handshake_destroy(tls);

see more code in:
https://github.com/lxin/tls_hs/tree/sunrpc

### 5. TCP sockopt usage:

An TCP socket option (TLS_HS_TCP) is added as a good example of how TLS_HS_GEN
can be used in kernel, and also provides a way to do testing for TLS_HS_GEN
APIs by userspace.

see more code in:
https://github.com/lxin/tls_hs/tree/tcp
and testing in:
https://github.com/lxin/tls_hs-tests#i-tls_hs_tcp

## The implementation:

  The implementation is pretty straightforward, no callback functions, no
  virtual functions, just use the kernel crypto APIs to complete the TLS
  handshake. I put it under crypto, as it calls too many crypto APIs
  including certificates parsing which can not be used outside of the
  kernel crypto.

  - include/crypto/tls_hs.h
  - crypto/tls_hs.c

  This can be enabled by:

    CONFIG_CRYPTO_TLS_HS=m/y

### 1. State Transition:

  To make the coding simple, different from RFC, only four states are
  defined, as only in these states some work needs to be done, like: in
  TLS_ST_RCVD state, the server needs to install early keys if needed
  and create the EE packet then install application keys, the client
  needs to install the handshake keys. See "QUIC usage" part.

     Client                                   Server

    TLS_ST_START           CH             TLS_ST_START
                     ------------->
    ---------------------------------------------------
                           SH
                     <-------------
    TLS_ST_RCVD            EE              TLS_ST_RCVD
                     <-------------
    TLS_ST_WAIT        CRT ... FIN
                     <-------------
                                           TLS_ST_WAIT
    ---------------------------------------------------
                       CRT ... FIN
                     ------------->
    TLS_ST_CONNECTED                  TLS_ST_CONNECTED

### 2. Ciphers & Algorithms:

  Currently only one cipher or algorithm is supported for each, and I chose
  the most popular one for each. The client will only use this combination to
  negotiate with the server, if the server doesn't support it, a Hello Retry
  Request will be sent as a reply, then the client returns an error, as it has
  no other options.

  - HKDF extract/expand: hmac(sha256)
  - ECDH key exchange: secp256r1(0x0017)
  - PSK exchange mode: psk_dhe_ke(1)
  - Certificate: rsa_pkcs1_sha256(0x0401)/rsa_pss_rsae_sha256(0x0804)
  - Signature Algorithm: rsa_pss_rsae_sha256(0x0804)
  - AEAD: TLS_AES_128_GCM_SHA256(0x1301)

### 3. Functions:

  These are the main features we support in this implementation, just note:
  There is a size limitation on Early Data as only 1 page is reserved for its
  sending and receiving. For Hello Retry Request, the client will abort after
  receiving it as only 1 combination support for ciphers and algorithms.

  - Certificate Chain and CA on Both Sides
  - PSK
  - Session Resumption
  - Early Data
  - Hello Retry Request on Server

### 4. Messages & Extensions:

  Since we don't support TLS old versions and all features, quite some
  messages and extensions can be skipped or aborted during handshake.
  The messages and extensions below are those that really get handled.

    - Messages:
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

    - Extensions:
      TLS_EXT_server_name             0
      TLS_EXT_supported_groups        10
      TLS_EXT_ec_point_formats        11
      TLS_EXT_signature_algorithms    13
      TLS_EXT_padding                 21
      TLS_EXT_session_ticket          35
      TLS_EXT_psk                     41
      TLS_EXT_early_data              42
      TLS_EXT_supported_versions      43
      TLS_EXT_psk_kex_modes           45
      TLS_EXT_signature_algs_cert     50
      TLS_EXT_key_share               51

### 5. Memory Management:

  An Object is allocated to save the context during the handshake:
  'struct tls_hs', like SSL object in openssl in user space, includes
  the information below:

  Some fields are pre-allocated, like msg: used for saving the TLS msgs
  generated to send out, and cmsg: used for buffering the uncomplete TLS
  msg; and ext: the extra extensions you want to add or the extensions
  unknown to TLS handshake processing so that we don't have to allocate
  them every time.

    - Creating and Parsing msgs:
      struct tls_hello h; /* client/server hello info used to negotiate */
      struct tls_vec ext; /* 1 page */
      struct tls_vec cmsg; /* 1 page */
      struct tls_vec msg; /* 1 page */

    - Secrets and HS msg buffers:
      struct tls_vec buf[TLS_B_MAX]; /* keep all TLS msgs to calculate hashes */
      struct tls_vec srt[TLS_SE_MAX]; /* all levels of secrets */

    - State and Flags:
      u8 state:2, early:1, is_serv:1, crt_req:1;

    - Crypto API algorithm objects:
      struct crypto_kpp *kpp_tfm; /* ECDH */
      struct crypto_aead *aead_tfm;
      struct crypto_shash *srt_tfm; /* HKDF */
      struct crypto_shash *hash_tfm;
      struct crypto_akcipher *akc_tfm; /* Signature */

    - Certs and Keys:
      struct tls_vec pkey;
      struct tls_crt *tcrts; /* the certificates configured to sends out */
      struct tls_crt *rcrts; /* the certificates received from the peer */
      struct tls_crt *ca;
      struct tls_psk *psks;

## The Security Issues:

  These are some very valuable feedbacks other developers, which should be
  solved before moving forward:

  - Certificate management is complex and not handled in the kernel
  - New encryptions introduced will have to be implemented in the kernel and
    it will be hard
  - Corner cases will cause problems with the kernel implementation
  - Will need to completely rewrite RSA code in the kernel
  - Kernel mpi code is not constant-time safe
  - DH and ECDH are also potentially broken
  - Will be important to do Handshake in the userspace to take advantage of
    decades of work.. See for example what primitives are necessary for secure
    RSA: https://gmplib.org/~tege/modexp-silent.pdf
