(ns clojstash.core
  (:gen-class)
  (:use [amazonica.aws.dynamodbv2])
  (:import (org.bouncycastle.crypto.params KeyParameter)
           (org.bouncycastle.crypto.modes SICBlockCipher)
           (org.bouncycastle.crypto.engines AESEngine))
  (:require [base64-clj.core :as base64]))


(defn getSicCipher
  "Return an AES cipher in SIC (CTR) mode. Configure using key, and set toEncrypt"
  [key toEncrypt?]
  ;; TODO: make sure key is 32 bytes long
  (let [engine (new AESEngine)]
    (. engine init toEncrypt? (new KeyParameter (.getBytes key)))
    (new SICBlockCipher engine)))

(defn encrypt
  "Encrypt plaintext with key using AWS in SIC (CTR) mode. Returns B64-encoded ciphertext string"
  [plaintext key]
  (let [cipher (getSicCipher key true)
        plainBytes (.getBytes plaintext)
        plainLen (count plainBytes)
        cipherBytes (byte-array plainLen)]
    (. cipher processBytes plainBytes 0 plainLen cipherBytes 0)
    (apply str (map char (base64/encode-bytes cipherBytes)))))

(defn listSecrets
  "Return a list of secrets and their version in the credential store"
  ;; Right now region gets ignored
  [& {:keys [region table]
      :or {region "us-east-1"
           table "credential-store"}}]
  (:items
   (scan
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




(defn -main
  "I don't do a whole lot."
  []
  (printSecrets :region "us-east-1" :table "credential-store"))
