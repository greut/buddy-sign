(ns buddy.sign.itsdangerous
  "ItsDangerous Signature implementation."
  (:require [buddy.core.codecs :as codecs]
            [buddy.core.codecs.base64 :as b64]
            [buddy.core.mac :as mac]
            [buddy.core.dsa :as dsa]
            [buddy.sign.util :as util]
            [buddy.util.ecdsa :refer [transcode-to-der transcode-to-concat]]
            [clojure.string :as str]
            [cheshire.core :as json]))

(def +signers-map+
  "Supported algorithms."
  {:hs1 {:signer   #(mac/hash %1 {:alg :hmac+sha1 :key %2})
         :verifier #(mac/verify %1 %2 {:alg :hmac+sha1 :key %3})}})


(defn- encode-payload
  [payload]
  (-> payload
      (b64/encode true)
      (codecs/bytes->str)))

(defn- decode-payload
  [payload]
  (b64/decode payload))

(defn- derive-key
  "This method is called to devie the key. Use large random secret keys."
  [{:keys [key alg salt]}]
  (let [signer (get-in +signers-map+ [alg :signer])]
    (signer salt key)))

(defn- calculate-signature
  "Given the bunch of bytes, a private key and algorithm,
  return a calculated signature as byte array."
  [{:keys [alg payload] :as args}]
  (let [signer (get-in +signers-map+ [alg :signer])
        dkey    (derive-key args)]
    (encode-payload (signer payload dkey))))

(defn- split-itsdangerous-message
  [message]
  (str/split message #"\." 3))

(defn- verify-signature
  "Given a bunch of bytes, a previously generated
  signature, the private key and algorithm, return
  signature matches or not."
  [{:keys [alg signature payload] :as args}]
  (let [verifier  (get-in +signers-map+ [alg :verifier])
        dkey      (derive-key args)
        signature (b64/decode signature)]
    (verifier payload signature dkey)))

(defn- truncate
  [xs start end]
  (byte-array
    (for [i (range start end)]
         (aget xs i))))

(defn timed-sign
  "Sign arbitrary length string/byte array using
  json web token/signature."
  [payload pkey & [{:keys [alg salt ts] :or {alg :hs1 salt "itsdangerous"} :as opts}]]
  {:pre [payload]}
    ;; XXX itsdangerous like int
    (let [timestamp (encode-payload (truncate (codecs/long->bytes (or ts (util/now))) 4 8))
        payload'   (encode-payload (str/join "." [payload timestamp]))
        signature (calculate-signature {:key pkey
                                        :alg alg
                                        :salt salt
                                        :payload payload'})]
    (str/join "." [payload' timestamp signature])))


(defn sign
  "Sign arbitrary length string/byte array using
  json web token/signature."
  [payload pkey & [{:keys [alg salt] :or {alg :hs1 salt "itsdangerous"} :as opts}]]
  {:pre [payload]}
  (let [payload (encode-payload payload)
        signature (calculate-signature {:key pkey
                                        :alg alg
                                        :salt salt
                                        :payload payload})]
    (str/join "." [payload signature])))


(defn unsign
  "Given a signed message, verify it and return
  the decoded payload."
  ([input pkey {:keys [alg salt] :or {alg :hs1 salt "itsdangerous"}}]
   (let [[payload ts signature] (split-itsdangerous-message input)
         [ts signature]         (if signature [ts signature] [nil ts])]
     (when-not
       (try
         (verify-signature {:key       pkey
                            :signature signature
                            :alg       alg
                            :salt      salt
                            :payload   payload})
         (catch java.security.SignatureException se
           (throw (ex-info "Message seems corrupt or manipulated."
                           {:type :validation :cause :signature}
                           se))))
       (throw (ex-info "Message seems corrupt or manipulated."
                       {:type :validation :cause :signature})))
     (decode-payload payload))))
