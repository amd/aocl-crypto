((nil 
  (eval . (let ((root (projectile-project-root)))
            (setq-local company-clang-arguments
                        (list (concat "-I" root "include")
                              (concat "-I" root "lib/include")))
            (setq-local flycheck-clang-include-path
                        (list (concat root "include")
                              (concat root "lib/include")))))))
