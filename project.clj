(defproject clojure-fedcm "0.1.0-SNAPSHOT"
  :description "FIXME: Google FedCM Sample"
  :url "http://example.com/FIXME"
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.11.1"]
               [ring/ring-core "1.12.2"]
               [ring/ring-jetty-adapter "1.12.2"]
               [compojure "1.7.1"]]
  :main ^:skip-aot clojure-fedcm.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all
                       :jvm-opts ["-Dclojure.compiler.direct-linking=true"]}})
