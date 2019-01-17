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


(defn- encode-header
  [header]
  (-> header
      (json/generate-string)
      (b64/encode true)
      (codecs/bytes->str)))

(defn- parse-header
  [^String data]
  (try
    (let [header (-> (b64/decode data)
                     (codecs/bytes->str)
                     (json/parse-string true))]
      (when-not (map? header)
        (throw (ex-info "Message seems corrupt or manipulated."
                        {:type :validation :cause :header})))
      (update header :alg #(keyword (str/lower-case %))))
    (catch com.fasterxml.jackson.core.JsonParseException e
      (throw (ex-info "Message seems corrupt or manipulated."
                      {:type :validation :cause :header})))))

(defn- encode-payload
  [input]
  (-> (b64/encode input true)
      (codecs/bytes->str)))

(defn- decode-payload
  [payload]
  (b64/decode payload))

(defn- calculate-signature
  "Given the bunch of bytes, a private key and algorithm,
  return a calculated signature as byte array."
  [{:keys [key alg header payload]}]
  (let [signer (get-in +signers-map+ [alg :signer])
        authdata (str/join "." [header payload])]
    (-> (signer authdata key)
        (b64/encode true)
        (codecs/bytes->str))))

(defn- split-itsdangerous-message
  [message]
  (str/split message #"\." 3))

(defn- verify-signature
  "Given a bunch of bytes, a previously generated
  signature, the private key and algorithm, return
  signature matches or not."
  [{:keys [alg signature key header payload]}]
  (let [verifier (get-in +signers-map+ [alg :verifier])
        authdata (str/join "." [header payload])
        signature (b64/decode signature)]
    (verifier authdata signature key)))


(defn sign
  "Sign arbitrary length string/byte array using
  json web token/signature."
  [payload pkey & [{:keys [alg header] :or {alg :hs1} :as opts}]]
  {:pre [payload]}
  (let [header (-> (merge {:alg alg} header)
                   (encode-header))
        payload (encode-payload payload)
        signature (calculate-signature {:key pkey
                                        :alg alg
                                        :header header
                                        :payload payload})]
    (str/join "." [header payload signature])))


(defn unsign
  "Given a signed message, verify it and return
  the decoded payload."
  ([input pkey] (unsign input pkey nil))
  ([input pkey {:keys [alg] :or {alg :hs1}}]
   (let [[header payload signature] (split-itsdangerous-message input)
         header-data (parse-header header)]
     (when-not
       (try
         (verify-signature {:key       (util/resolve-key pkey header-data)
                            :signature signature
                            :alg       alg
                            :header    header
                            :payload   payload})
         (catch java.security.SignatureException se
           (throw (ex-info "Message seems corrupt or manipulated."
                           {:type :validation :cause :signature}
                           se))))
       (throw (ex-info "Message seems corrupt or manipulated."
                       {:type :validation :cause :signature})))
     (decode-payload payload))))
