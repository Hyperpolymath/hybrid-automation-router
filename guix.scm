;; hybrid-automation-router - Guix Package Definition
;; Run: guix shell -D -f guix.scm

(use-modules (guix packages)
             (guix gexp)
             (guix git-download)
             (guix build-system mix)
             ((guix licenses) #:prefix license:)
             (gnu packages base))

(define-public hybrid_automation_router
  (package
    (name "hybrid-automation-router")
    (version "0.1.0")
    (source (local-file "." "hybrid-automation-router-checkout"
                        #:recursive? #t
                        #:select? (git-predicate ".")))
    (build-system mix-build-system)
    (synopsis "Elixir application")
    (description "Elixir application - part of the RSR ecosystem.")
    (home-page "https://github.com/hyperpolymath/hybrid-automation-router")
    (license license:agpl3+)))

;; Return package for guix shell
hybrid_automation_router
