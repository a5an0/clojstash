(ns clojstash.core
  (:gen-class)
  (:require [base64-clj.core :as base64]
            [amazonica.aws.dynamodbv2 :as ddb]
            [amazonica.aws.kms :as kms])
  (:import (java.nio ByteBuffer))
  (:use clojstash.crypto))

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

(defn getSecret
  [name]
  (let [item (first (:items (ddb/query
              :table-name "credential-store"
              :expression-attribute-values {":name" {:s name}}
              :expression-attribute-names {"#n" "name"}
              :key-condition-expression "#n = :name"
              :limit 1
              :scan-index-forward false)))
        cipherText (:contents item)
        ;; unwrappedKey (kms/decrypt
        ;;               :ciphertext-blob (ByteBuffer/wrap
        ;;                                (base64/decode-bytes
        ;;                                 (. (:key item) getBytes "UTF8"))))]
        unwrappedKey (->> item
                          :key
                          ((fn [i] (. i getBytes "UTF8")))
                          base64/decode-bytes
                          ByteBuffer/wrap
                          (kms/decrypt :ciphertext-blob)
                          :plaintext
                          .array)]
    (decrypt cipherText (byte-array (take 32 unwrappedKey)))
    ))
    
    

(defn -main
  "I don't do a whole lot."
  []
  (printSecrets :region "us-east-1" :table "credential-store"))
