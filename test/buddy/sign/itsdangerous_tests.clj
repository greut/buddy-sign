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
            [buddy.sign.util :as util]
            [cheshire.core :as json]))

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

(deftest itsdangerous-wrong-key
  (let [candidate "foo bar "
        result    (itsdangerous/sign candidate "key" {:alg :hs1})]
    (unsign-exp-fail result :signature)))

(deftest itsdangerous-simple-unsign
  (is (bytes/equals? (codecs/to-bytes (json/generate-string [1 2 3 4]))
                     (itsdangerous/unsign "WzEsMiwzLDRd.X9jM62WJ1vHLTock5MeU_bwqh2A" "secret-key" {:alg :hs1})))
  (is (bytes/equals? (codecs/to-bytes (json/generate-string [1 2 3 4]))
                     (itsdangerous/unsign "WzEsMiwzLDRd.XElmcA.X9jM62WJ1vHLTock5MeU_bwqh2A" "secret-key" {:alg :hs1})))
  )

(deftest itsdangerous-simple-sign
  (is (= "WzEsMiwzLDRd.X9jM62WJ1vHLTock5MeU_bwqh2A"
         (itsdangerous/sign (json/generate-string [1 2 3 4]) "secret-key" {:alg :hs1}))))

(defspec itsdangerous-spec-alg-hs 500
  (props/for-all
   [key (gen/one-of [gen/bytes gen/string])
    data (gen/one-of [gen/bytes gen/string])
    alg (gen/elements [:hs1])]
   (let [res1 (itsdangerous/sign data key {:alg alg})
         res2 (itsdangerous/unsign res1 key {:alg alg})]
     (is (bytes/equals? res2 (codecs/to-bytes data))))))

(defspec itsdangerous-timed-spec-alg-hs 500
  (props/for-all
   [key (gen/one-of [gen/bytes gen/string])
    data (gen/one-of [gen/bytes gen/string])
    alg (gen/elements [:hs1])]
   (let [res1 (itsdangerous/timed-sign data key {:alg alg})
         res2 (itsdangerous/unsign res1 key {:alg alg})]
     (is (bytes/equals? res2 (codecs/to-bytes data))))))
 
