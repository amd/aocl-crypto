((nil . ((setq enable-local-eval t)
         (projectile-project-name . "aocl-crypto")
         ;;(projectile-project-root . "~/Projects/amd/aocl-crypto.git")
         (projectile-enable-caching . t)

         (eval . (setq-local flycheck-clang-include-path
                             (list (expand-file-name "include" (projectile-project-root))
                                   (expand-file-name "lib/include" (projectile-project-root)))))))

 (cc-mode . ((eval . (setq clang-args ("-Iinclude"
                                       "-Ilib/include")
                           (flycheck-clang-include-path ("include" "lib/include"))
                           (company-clang-arguments . clang-args)

                           (flycheck-clang-args . clang-args)))))
 (markdown . ((eval . (wc-mode 1))))
 )

