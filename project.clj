(defproject clojure-fedcm "0.1.0-SNAPSHOT"
  :description "FIXME: Google FedCM Sample"
  :url "http://example.com/FIXME"
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.11.1"]
               [ring/ring-core "1.12.2"]
               [ring/ring-jetty-adapter "1.12.2"]
                 [ring/ring-json "0.5.1"] 
                 [lynxeyes/dotenv "1.1.0"]
               [compojure "1.7.1"] 
                 [clj-http "3.12.3"]
                 [cheshire "5.10.0"]
                 [buddy/buddy-sign "3.4.1"]
                 [buddy/buddy-core "1.10.1"] 
                 [com.auth0/java-jwt "3.18.2"]
                 [com.auth0/jwks-rsa "0.20.0"]]
  :main ^:skip-aot clojure-fedcm.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all
                       :jvm-opts ["-Dclojure.compiler.direct-linking=true"]}})
