(ns clojure-fedcm.core
  (:require [compojure.core :refer [defroutes GET POST]]
            [compojure.route :as route]
            [ring.middleware.params :refer [wrap-params]]
            [ring.middleware.keyword-params :refer [wrap-keyword-params]]
            [ring.util.response :refer [response redirect]]
            [ring.adapter.jetty :refer [run-jetty]]
            [ring.middleware.session :refer [wrap-session]]
            [clojure.java.io :as io]
            [clojure.string :as str]))

(def sessions (atom {}))

(defn load-template [file]
  (slurp (io/resource (str "templates/" file))))

(defn login-page []
  (response (load-template "login.html")))

(defn home-page [username]
  (let [html (load-template "home.html")]
    (response (str/replace html "{{username}}" username))))

(defn logout []
  (response (redirect "/login")))

(defn handle-login [request]
  (let [form-params (:form-params request)
        username (get form-params "username")
        password (get form-params "password")]
    (println (format "Login attempt - Username: %s, Password: %s" username password))
    (if (= password "secret")
      (do
        (swap! sessions assoc username true)
        (-> (redirect "/")
            (assoc-in [:session :username] username)))
      (response "<h1>Invalid username or password</h1>"))))

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
      (wrap-session {:cookie-attrs {:http-only true}})))

(defn -main []
  (run-jetty app {:port 4545 :join? false}))
