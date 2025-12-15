;; SPDX-License-Identifier: AGPL-3.0-or-later
;; SPDX-FileCopyrightText: 2025 Jonathan D.A. Jewell
;; ECOSYSTEM.scm — hybrid-automation-router

(ecosystem
  (version "1.0.0")
  (name "hybrid-automation-router")
  (type "project")
  (purpose "*Think BGP for infrastructure automation.* HAR treats configuration management like network packet routing - it parses configs from any IaC tool (Ansible, Salt, Terraform, bash), extracts semantic ope...")

  (position-in-ecosystem
    "Part of hyperpolymath ecosystem. Follows RSR guidelines.")

  (related-projects
    (project (name "rhodium-standard-repositories")
             (url "https://github.com/hyperpolymath/rhodium-standard-repositories")
             (relationship "standard")))

  (what-this-is "*Think BGP for infrastructure automation.* HAR treats configuration management like network packet routing - it parses configs from any IaC tool (Ansible, Salt, Terraform, bash), extracts semantic ope...")
  (what-this-is-not "- NOT exempt from RSR compliance"))
