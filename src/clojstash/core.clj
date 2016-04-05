(ns clojstash.core
  (:gen-class)
  (:import (org.bouncycastle.crypto.params KeyParameter)
           (org.bouncycastle.crypto.modes SICBlockCipher)
           (org.bouncycastle.crypto.engines AESEngine)
           (java.nio ByteBuffer))
  (:require [base64-clj.core :as base64]
            [amazonica.aws.dynamodbv2 :as ddb]
            [amazonica.aws.kms :as kms]))


(defn listSecrets
  "Return a list of secrets and their version in the credential store"
  ;; Right now region gets ignored
  [& {:keys [region table]
      :or {region "us-east-1"
           table "credential-store"}}]
  (:items
   (ddb/scan
    :table-name table
    :attributes-to-get '["name" "version"])))

(defn printSecrets
  "Pretty-print secrets and versions"
  [& {:keys [region table]
      :or {region "us-east-1"
           table "credential-store"}}]
  (println
   (clojure.string/join "\n"
    (map
     (fn [x]
       (format "%s -- version %s" (:name x) (:version x)))
     (listSecrets region table)))))

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

(defn putSecret
  "Put a secret into the secret store"
  ;; TODO: implement region and table switching
  [name secret version kms-key]
  (let [kmsResp (kms/generate-data-key :key-id "alias/credstash" :number-of-bytes 64) ;; 32 bytes for encrypt, 32 for hmac
        wrappedKey (String. (base64/encode-bytes (.array (:ciphertext-blob kmsResp))))
        dataKey (byte-array (take 32 (.array (:plaintext kmsResp))))
        hmacKey (byte-array (drop 32 (.array (:plaintext kmsResp))))]
    (ddb/put-item
     :table-name "credential-store"
     :item {
            :name name
            :version (str version)
            :contents (encrypt secret dataKey)
            :key wrappedKey
            :hmac (hmac secret hmacKey)
            })))


(defn -main
  "I don't do a whole lot."
  []
  (printSecrets :region "us-east-1" :table "credential-store"))
