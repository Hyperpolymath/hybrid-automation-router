;;; STATE.scm - Hybrid Automation Router (HAR)
;;; Download this file at end of each session!
;;; At start of next conversation, upload it.
;;; ===========================================

;;;------------------------------------------
;;; METADATA
;;;------------------------------------------
(define-module (har state)
  #:export (state-version
            last-updated
            project-status))

(define state-version "1.0.0")
(define last-updated "2025-12-08")
(define generator "claude-opus-4")

;;;------------------------------------------
;;; PROJECT CONTEXT
;;;------------------------------------------
(define project
  '((name . "HAR - Hybrid Automation Router")
    (repo . "hyperpolymath/hybrid-automation-router")
    (license . "MIT")
    (description . "BGP for infrastructure automation - parses IaC configs and routes/transforms to any target format")
    (tech-stack . (elixir otp yaml-elixir libgraph))
    (phase . "poc")
    (current-version . "0.1.0")))

;;;------------------------------------------
;;; CURRENT POSITION
;;;------------------------------------------
(define current-position
  '((phase . "Phase 1: POC")
    (overall-completion . 45)
    (focus . "Core transformation pipeline")
    (blocking-items . ())
    (last-session-work . "Initial project analysis and state documentation")))

(define implementation-status
  '(;; COMPLETED
    (architecture-docs
     (status . complete)
     (completion . 100)
     (notes . "Full architecture documented in docs/"))

    (elixir-project-setup
     (status . complete)
     (completion . 100)
     (notes . "mix.exs configured with all core dependencies"))

    (semantic-graph-models
     (status . complete)
     (completion . 100)
     (files . ("lib/har/semantic/graph.ex"
               "lib/har/semantic/operation.ex"
               "lib/har/semantic/dependency.ex"))
     (notes . "Graph with topological sort, partitioning, merging"))

    (ansible-parser
     (status . complete)
     (completion . 95)
     (files . ("lib/har/data_plane/parsers/ansible.ex"))
     (tests . ("test/data_plane/parsers/ansible_test.exs"))
     (notes . "Handles apt/yum/service/copy/file/user/command modules")
     (remaining . ("Handler/notify dependency extraction"
                   "Conditional (when) dependency modeling")))

    (salt-parser
     (status . complete)
     (completion . 90)
     (files . ("lib/har/data_plane/parsers/salt.ex"))
     (notes . "Parses SLS files, extracts require/watch/prereq deps")
     (remaining . ("Pillar data handling"
                   "Jinja template detection")))

    (salt-transformer
     (status . complete)
     (completion . 85)
     (files . ("lib/har/data_plane/transformers/salt.ex"))
     (notes . "Generates Salt SLS from semantic graph")
     (remaining . ("Requisite generation"
                   "State ordering optimization")))

    (routing-engine
     (status . complete)
     (completion . 80)
     (files . ("lib/har/control_plane/router.ex"
               "lib/har/control_plane/routing_table.ex"))
     (notes . "Pattern-based routing, YAML routing table, backend selection")
     (remaining . ("Health checking integration"
                   "Policy engine integration")))

    ;; IN PROGRESS
    (ansible-transformer
     (status . not-started)
     (completion . 0)
     (notes . "Transformer file exists but implementation pending"))

    (terraform-parser
     (status . not-started)
     (completion . 0)
     (notes . "HCL parsing needed - consider using existing HCL library"))

    (ipfs-integration
     (status . stub)
     (completion . 15)
     (files . ("lib/har/ipfs/node.ex"))
     (notes . "GenServer skeleton only, mock CID generation")
     (remaining . ("ex_ipfs actual integration"
                   "Content addressing workflow"
                   "Pin management")))

    (security-manager
     (status . stub)
     (completion . 10)
     (files . ("lib/har/security/manager.ex"))
     (notes . "GenServer skeleton, TLS config loading")
     (remaining . ("Certificate validation"
                   "Policy-based authorization"
                   "Audit logging")))

    (cli-demo
     (status . not-started)
     (completion . 0)
     (notes . "No CLI implemented yet"))

    (integration-tests
     (status . partial)
     (completion . 20)
     (notes . "Unit tests exist for parser/graph, need E2E pipeline tests"))))

;;;------------------------------------------
;;; ROUTE TO MVP V1
;;;------------------------------------------
(define mvp-v1-requirements
  '((description . "Demonstrate Ansible -> Salt transformation end-to-end")
    (target-completion . "Phase 1 POC")
    (critical-path
     . ((step-1 "Complete Ansible transformer (reverse direction)")
        (step-2 "Integration test: Ansible -> Semantic Graph -> Salt")
        (step-3 "CLI tool for transformation demo")
        (step-4 "Basic IPFS storage for configs")
        (step-5 "Documentation + example playbooks")))))

(define mvp-v1-tasks
  '(;; HIGH PRIORITY - Must complete for MVP
    ((task . "Create CLI mix task for transformation")
     (priority . high)
     (status . pending)
     (estimate . "2-4 hours")
     (details . "mix har.convert --from ansible --to salt playbook.yml"))

    ((task . "Integration test for full pipeline")
     (priority . high)
     (status . pending)
     (estimate . "3-4 hours")
     (details . "Test Ansible YAML -> parse -> route -> transform -> Salt SLS"))

    ((task . "Example playbooks with transformations")
     (priority . high)
     (status . pending)
     (estimate . "2-3 hours")
     (details . "Create examples/ with working Ansible->Salt conversions"))

    ((task . "Implement Ansible transformer")
     (priority . medium)
     (status . pending)
     (estimate . "4-6 hours")
     (details . "Generate Ansible playbook from semantic graph"))

    ;; MEDIUM PRIORITY - Important for demo
    ((task . "IPFS content storage implementation")
     (priority . medium)
     (status . pending)
     (estimate . "4-6 hours")
     (details . "Store/retrieve configs via ex_ipfs"))

    ((task . "Service control operation type handling")
     (priority . medium)
     (status . pending)
     (details . "Currently parses but routing needs service_control->service_start/stop split"))

    ;; LOWER PRIORITY - Nice to have for MVP
    ((task . "Terraform HCL parser")
     (priority . low)
     (status . pending)
     (details . "Would expand tool coverage significantly"))

    ((task . "Web endpoint for transformation API")
     (priority . low)
     (status . pending)
     (files . ("lib/har/web/endpoint.ex"))
     (details . "REST API wrapper around transform functions"))))

;;;------------------------------------------
;;; KNOWN ISSUES
;;;------------------------------------------
(define issues
  '(((id . 1)
     (type . bug)
     (severity . low)
     (title . "service_control type ambiguity")
     (description . "Ansible parser outputs :service_control but Salt transformer expects :service_start/:service_stop")
     (location . "lib/har/data_plane/parsers/ansible.ex:122-123")
     (resolution . "Map service state in parser or add routing normalization"))

    ((id . 2)
     (type . limitation)
     (severity . medium)
     (title . "YamlElixir.write_to_string may not exist")
     (description . "Salt transformer uses YamlElixir.write_to_string which may not be in yaml_elixir API")
     (location . "lib/har/data_plane/transformers/salt.ex:221")
     (resolution . "Use Jason for intermediate step or yaml_encoder library"))

    ((id . 3)
     (type . todo)
     (severity . low)
     (title . "IPFS not implemented")
     (description . "IPFS integration is mocked - store/retrieve return fake data")
     (location . "lib/har/ipfs/node.ex"))

    ((id . 4)
     (type . todo)
     (severity . medium)
     (title . "Health checking TODO")
     (description . "Router assumes all backends healthy - needs HealthChecker integration")
     (location . "lib/har/control_plane/router.ex:98-101"))

    ((id . 5)
     (type . todo)
     (severity . medium)
     (title . "Policy engine TODO")
     (description . "Policy filtering is pass-through - needs PolicyEngine integration")
     (location . "lib/har/control_plane/router.ex:104-109"))))

;;;------------------------------------------
;;; QUESTIONS FOR USER
;;;------------------------------------------
(define questions
  '(((priority . high)
     (question . "Should MVP demo focus solely on Ansible<->Salt, or include Terraform?")
     (context . "Terraform parser is not started; adding it would expand scope"))

    ((priority . high)
     (question . "Is CLI-based demo sufficient, or do we need web UI?")
     (context . "Web endpoint exists as skeleton but would need frontend"))

    ((priority . medium)
     (question . "Which IPFS implementation to target: local node or Infura/Pinata gateway?")
     (context . "Affects ex_ipfs configuration and deployment complexity"))

    ((priority . medium)
     (question . "Target deployment: Podman-compose first, or direct Kubernetes?")
     (context . "SELF_HOSTED_DEPLOYMENT.md mentions both"))

    ((priority . low)
     (question . "Should routing table be embedded or loaded from external file?")
     (context . "Currently loads from priv/routing_table.yaml if exists"))))

;;;------------------------------------------
;;; LONG TERM ROADMAP
;;;------------------------------------------
(define roadmap
  '((phase-1
     (name . "POC")
     (timeline . "3-6 months")
     (status . in-progress)
     (completion . 45)
     (goals . ("Working Elixir prototype"
               "Ansible/Salt parsers"
               "Basic routing engine"
               "CLI demo"
               "Self-hosted Podman deployment"))
     (deliverables . ("mix har.convert CLI"
                      "Example transformations"
                      "IPFS config storage")))

    (phase-2
     (name . "Community")
     (timeline . "6-12 months")
     (status . future)
     (goals . ("Plugin architecture for parsers"
               "Web dashboard"
               "Distributed routing (OTP cluster)"
               "ML-based routing optimization"
               "Performance benchmarks"))
     (dependencies . ("Phase 1 complete"
                      "Community feedback")))

    (phase-3
     (name . "Standardization")
     (timeline . "1-2 years")
     (status . future)
     (goals . ("Draft IETF RFC specification"
               "Reference implementation compliance tests"
               "HAR Foundation governance"
               "Trademark protection"
               "Multi-vendor adoption"))
     (dependencies . ("Phase 2 complete"
                      "Production usage evidence"
                      "Industry partnerships")))))

;;;------------------------------------------
;;; ARCHITECTURE DECISIONS
;;;------------------------------------------
(define architecture-decisions
  '(((id . "ADR-001")
     (title . "Elixir/OTP over Haskell")
     (status . accepted)
     (rationale . "Faster development velocity, better distributed systems support, 'let it crash' philosophy"))

    ((id . "ADR-002")
     (title . "Semantic Graph as IR")
     (status . accepted)
     (rationale . "Tool-agnostic representation enables cross-tool transformation"))

    ((id . "ADR-003")
     (title . "IPFS for content addressing")
     (status . accepted)
     (rationale . "Immutable versioning, global dedup, verifiable deployments"))

    ((id . "ADR-004")
     (title . "TLS certificates for auth, MAC only for discovery")
     (status . accepted)
     (rationale . "MAC addresses are spoofable - certificates provide real security"))))

;;;------------------------------------------
;;; SESSION LOG
;;;------------------------------------------
(define session-log
  '(((date . "2025-12-08")
     (actions . ("Initial project analysis"
                 "Reviewed all implementation files"
                 "Assessed completion percentages"
                 "Created STATE.scm"))
     (files-modified . ("STATE.scm")))))

;;;------------------------------------------
;;; CRITICAL NEXT ACTIONS
;;;------------------------------------------
(define next-actions
  '(((priority . 1)
     (action . "Create CLI mix task: mix har.convert")
     (rationale . "Enables immediate demo capability"))

    ((priority . 2)
     (action . "Write integration test for Ansible->Salt pipeline")
     (rationale . "Validates full transformation chain works"))

    ((priority . 3)
     (action . "Fix service_control type normalization")
     (rationale . "Blocking correct service transformations"))

    ((priority . 4)
     (action . "Add example playbooks to examples/ansible/")
     (rationale . "Demonstrates value proposition"))

    ((priority . 5)
     (action . "Implement YamlElixir alternative for Salt output")
     (rationale . "Current approach may fail at runtime"))))

;;; ===========================================
;;; END OF STATE - Upload this at next session start
;;; ===========================================
