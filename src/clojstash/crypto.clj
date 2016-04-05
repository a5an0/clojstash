(ns clojstash.crypto
  (:import (org.bouncycastle.crypto.params KeyParameter)
           (org.bouncycastle.crypto.modes SICBlockCipher)
           (org.bouncycastle.crypto.engines AESEngine)
           (java.nio ByteBuffer))
  (:require [base64-clj.core :as base64])
  )

(defn getSicCipher
  "Return an AES cipher in SIC (CTR) mode. Configure using key, and set toEncrypt. Key must be a byte array"
  [key toEncrypt?]
  ;; TODO: make sure key is 32 bytes long
  (let [engine (new AESEngine)]
    (. engine init toEncrypt? (new KeyParameter key))
    (new SICBlockCipher engine)))

(defn encrypt
  "Encrypt plaintext with key using AWS in SIC (CTR) mode. Returns B64-encoded ciphertext string"
  [plaintext key]
  (let [cipher (getSicCipher key true)
        plainBytes (.getBytes plaintext)
        plainLen (count plainBytes)
        cipherBytes (byte-array plainLen)]
    (. cipher processBytes plainBytes 0 plainLen cipherBytes 0)
    (String. (base64/encode-bytes cipherBytes))))

(defn hmac
  [value key]
  '("yep"))
