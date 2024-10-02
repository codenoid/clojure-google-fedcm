(ns clojure-fedcm.core
  (:require [compojure.core :refer [defroutes GET POST]]
            [compojure.route :as route]
            [ring.middleware.params :refer [wrap-params]]
            [ring.middleware.keyword-params :refer [wrap-keyword-params]]
            [ring.middleware.json :refer [wrap-json-response]]
            [ring.util.response :refer [response redirect]]
            [ring.adapter.jetty :refer [run-jetty]]
            [ring.middleware.session :refer [wrap-session]]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clj-http.client :as http]
            [cheshire.core :as json]
            [buddy.sign.jwt :as jwt]
            [buddy.core.keys :as keys]
            [dotenv :refer [env app-env]])
  (:import (com.auth0.jwk JwkProviderBuilder)
           (com.auth0.jwt.algorithms Algorithm)
           (com.auth0.jwt JWT)
           [org.apache.commons.codec.binary Base64]))

(def public-google-client-id (env :GOOGLE_CLIENT_ID))

(def jwk-provider
  (-> (JwkProviderBuilder. "https://www.googleapis.com/oauth2/v3/certs")
      (.build)))

;; FIX LATER
(defn verify-jwt [token]
  (try
    (let [decoded-jwt (JWT/decode token)
          kid (.getKeyId decoded-jwt)]
      (print (str "Decoded JWT payload: " (.getPayload decoded-jwt)))
      (print (str "Key ID (kid): " kid))
      (let [public-key (.getPublicKey (.get jwk-provider kid))]
        (print (str "Using public key: " public-key))
        (let [algorithm (Algorithm/RSA256 public-key nil)
              verifier (-> (JWT/require algorithm)
                           (.withIssuer "https://accounts.google.com")
                           (.withAudience (into-array [public-google-client-id]))
                           (.build))
              verified-token (.verify verifier decoded-jwt)]
          (.getSubject verified-token))))
    (catch Exception e
      (println "JWT verification failed:" (.getMessage e))
      nil)))

(defn decode-jwt [token]
  (try
    (-> token
        (str/split #"\.")
        second 
        Base64/decodeBase64
        String.
        json/decode
        )
    (catch Exception e
      (println "JWT decoding failed:" (.getMessage e))
      nil)))

(def sessions (atom {}))

(defn load-template [file]
  (slurp (io/resource (str "templates/" file))))

(defn login-page []
  (let [html (load-template "login.html")]
     (response (str/replace html "{{GOOGLE_CLIENT_ID}}" public-google-client-id))))

(defn home-page [username]
  (let [html (load-template "home.html")]
    (response (str/replace html "{{username}}" username))))

(defn logout []
  (response (redirect "/login")))

(defn handle-login [request]
  (let [credential (get-in request [:form-params "credential"])]
    (println "Received credential:" credential)
    (if-let [payload (decode-jwt credential)]
      (do
        (let [email-value (atom nil)]
          (doseq [[key value] payload]
            (when (= key "email")
              (reset! email-value value)))

          (let [email @email-value]
            (println "Extracted email:" email)
            (if email
              (do
                (swap! sessions assoc email true)
                (-> (response {:success true
                               :message "Login successful"
                               :user {:email email}})
                    (assoc-in [:session :username] email)))
              (do
                (println "Email is nil, cannot proceed.")
                (-> (response {:success false
                               :message "Invalid credential"})
                    (assoc :status 401)))))))
      (do
        (println "JWT verification failed, payload is nil or invalid.")
        (-> (response {:success false
                       :message "Invalid credential"})
            (assoc :status 401))))))

(defn logout []
  (-> (redirect "/login")
      (assoc :session nil)))

(defroutes app-routes
  (GET "/" request
    (if-let [username (get-in request [:session :username])]
      (home-page username)
      (redirect "/login")))

  (GET "/login" [] (login-page))

  (POST "/login" request
    (handle-login request))

  (GET "/logout" []
   (logout))

  (route/not-found "404 - Not Found"))

(def app
  (-> app-routes
      wrap-keyword-params
      wrap-params
      wrap-json-response
      (wrap-session {:cookie-attrs {:http-only true}})))

(defn -main []
  (run-jetty app {:port 4545 :host "localhost" :join? false})
  (println "running on http://localhost:4545")
  )
