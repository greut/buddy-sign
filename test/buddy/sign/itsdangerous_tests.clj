(ns buddy.sign.itsdangerous-tests
  (:require [clojure.test :refer :all]
            [clojure.test.check.clojure-test :refer (defspec)]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as props]
            [buddy.core.codecs :as codecs]
            [buddy.core.crypto :as crypto]
            [buddy.core.keys :as keys]
            [buddy.core.bytes :as bytes]
            [buddy.core.nonce :as nonce]
            [buddy.sign.itsdangerous :as itsdangerous]
            [buddy.sign.util :as util]))

(def secret "test")

(defn- unsign-exp-succ
  ([signed candidate]
   (unsign-exp-succ signed candidate nil))
  ([signed candidate opts]
   (is (bytes/equals? (itsdangerous/unsign signed secret opts)
                      (codecs/to-bytes candidate)))))

(defn- unsign-exp-fail
  ([signed cause]
   (unsign-exp-fail signed cause nil))
  ([signed cause opts]
   (try
     (itsdangerous/unsign signed secret opts)
     (throw (Exception. "unexpected"))
     (catch clojure.lang.ExceptionInfo e
       (is (= cause (:cause (ex-data e))))))))

(deftest jws-wrong-key
  (let [candidate "foo bar "
        result    (itsdangerous/sign candidate "key" {:alg :hs1})]
    (unsign-exp-fail result :signature)))
