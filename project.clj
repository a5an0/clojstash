(defproject clojstash "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [amazonica "0.3.52"]
                 [org.bouncycastle/bcprov-jdk15on "1.54"]
                 [base64-clj "0.1.1"]]
  :main clojstash.core
  :aot [clojstash.core])
