# JuliaML Security System - Practical Usage Examples
# Threat detection and response scenarios

using .JuliaMLSecurity

# Example 1: Detecting Metamorphic Code Injection
function example_metamorphic_detection()
    println("=== Metamorphic Code Injection Detection ===")
    
    # Initialize security system
    dashboard = quick_start_security()
    
    # Simulate suspicious code that might be injected
    suspicious_code = """
    function dynamic_loader(payload::String)
        # This pattern is often used in metamorphic malware
        decoded = base64decode(payload)
        expr = Meta.parse(String(decoded))
        
        # Dynamic evaluation - RED FLAG!
        result = eval(expr)
        
        # Self-modifying behavior
        @eval function new_behavior()
            \$result
        end
        
        return new_behavior
    end
    """
    
    # Write suspicious code to file
    test_file = "test_metamorphic.jl"
    open(test_file, "w") do f
        write(f, suspicious_code)
    end
    
    # Analyze with replicode
    analysis = analyze_file_with_ml(dashboard, test_file)
    
    println("Analysis Results:")
    println("- Metamorphic Risk: $(analysis["ml_predictions"]["metamorphic_risk"])")
    println("- Intent Classification: $(analysis["ml_predictions"]["intent"])")
    println("- Recommended Action: $(analysis["ml_predictions"]["intent"]["recommended_action"])")
    
    # Clean up
    rm(test_file, force=true)
    
    return dashboard
end

# Example 2: Behavioral Training Data Poisoning Detection
function example_training_poisoning_detection()
    println("\n=== Training Data Poisoning Detection ===")
    
    # Create security-aware ML architecture
    ml_arch = create_secure_ml_architecture()
    
    # Initialize security with specific monitoring for training data
    dashboard = start_integrated_security_system(
        ml_architecture = ml_arch,
        monitor_paths = ["models/", "data/", "training_logs/"],
        critical_files = ["BehavioralTrainingRegiment.jl", "training_data.jld2"]
    )
    
    # Monitor for suspicious training patterns
    add_training_monitors!(dashboard)
    
    # Simulate poisoned training data injection
    poisoned_data = Dict(
        "behavioral_patterns" => rand(100),  # Random noise
        "labels" => fill("malicious", 100),
        "injection_timestamp" => now()
    )
    
    # Detect anomalous training data
    is_poisoned = detect_training_anomaly(dashboard, poisoned_data)
    
    if is_poisoned
        println("⚠️  ALERT: Potential training data poisoning detected!")
        println("- Anomaly Score: $(poisoned_data["anomaly_score"])")
        println("- Affected Models: $(poisoned_data["affected_models"])")
        println("- Recommended: Rollback to last known good checkpoint")
    end
    
    return dashboard
end

# Example 3: Real-time Profile Manipulation Detection
function example_profile_manipulation()
    println("\n=== Profile Manipulation Detection ===")
    
    dashboard = quick_start_security()
    
    # Monitor ProfileTranslationArchitecture for unauthorized changes
    profile_monitor = ProfileIntegrityMonitor(dashboard)
    
    # Simulate unauthorized profile modification
    unauthorized_profile_change = """
    # Attacker trying to modify behavioral profiles
    profile = load_profile("legitimate_model")
    profile.risk_threshold = 0.0  # Disable risk detection
    profile.behavioral_patterns[:malicious] = false  # Hide malicious behavior
    save_profile("legitimate_model", profile)
    """
    
    # Detect the manipulation
    violation = detect_profile_tampering(profile_monitor, unauthorized_profile_change)
    
    if violation !== nothing
        println("🚨 CRITICAL: Profile tampering detected!")
        println("- Affected Profile: $(violation.profile_name)")
        println("- Changed Fields: $(violation.changed_fields)")
        println("- Integrity Check: FAILED")
        
        # Automatic remediation
        restore_profile_from_backup(violation.profile_name)
        println("✓ Profile restored from secure backup")
    end
    
    return profile_monitor
end

# Example 4: Distributed Attack Pattern Recognition
function example_distributed_attack_detection()
    println("\n=== Distributed Attack Pattern Detection ===")
    
    # Setup distributed monitoring across multiple nodes
    dashboard = deploy_distributed_security()
    
    # Define attack patterns specific to ML systems
    ml_attack_patterns = [
        # Model extraction attempts
        AttackPattern(
            name = "model_extraction",
            indicators = ["repeated_inference", "systematic_queries", "boundary_probing"],
            severity = :high
        ),
        
        # Adversarial example generation
        AttackPattern(
            name = "adversarial_generation",
            indicators = ["gradient_queries", "perturbation_testing", "misclassification_attempts"],
            severity = :critical
        ),
        
        # Data exfiltration
        AttackPattern(
            name = "data_exfiltration",
            indicators = ["bulk_data_access", "unusual_export_patterns", "compression_before_transfer"],
            severity = :critical
        )
    ]
    
    # Register attack patterns
    for pattern in ml_attack_patterns
        register_attack_pattern!(dashboard, pattern)
    end
    
    # Simulate distributed attack
    simulate_coordinated_attack(dashboard)
    
    # Check detection results
    detected_patterns = get_detected_attack_patterns(dashboard)
    
    println("Detected Attack Patterns:")
    for (pattern_name, confidence) in detected_patterns
        println("- $pattern_name: $(round(confidence * 100, digits=1))% confidence")
    end
    
    return dashboard
end

# Example 5: Automated Incident Response
function example_automated_response()
    println("\n=== Automated Incident Response ===")
    
    # Create response playbooks
    playbooks = create_response_playbooks()
    
    # Initialize system with automated response
    dashboard = deploy_security_system("advanced_config.yaml")
    
    # Configure automated responses
    configure_automated_responses!(dashboard, playbooks)
    
    # Simulate various incidents
    incidents = [
        FileViolation("models/production_model.jld2", "hash1", "hash2", now(), :critical),
        ProcessViolation(12345, "suspicious_julia", "memory_injection", now(), :high),
        NetworkViolation("192.168.1.100", "external_c2.com", 443, "tcp", now(), :critical)
    ]
    
    println("Simulating security incidents...")
    
    for incident in incidents
        println("\nIncident: $(typeof(incident))")
        
        # Trigger automated response
        response = handle_incident_automatically(dashboard, incident)
        
        println("Automated Response:")
        println("- Actions Taken: $(response.actions)")
        println("- Isolation Status: $(response.isolation_complete)")
        println("- Evidence Collected: $(response.evidence_path)")
        println("- Recovery ETA: $(response.recovery_eta)")
    end
    
    return dashboard
end

# Helper Functions

function create_secure_ml_architecture()
    # Create ML architecture with security hardening
    registry = ModuleProfileRegistry()
    
    # Add security validators
    registry.add_validator(profile -> validate_profile_integrity(profile))
    registry.add_validator(profile -> check_behavioral_bounds(profile))
    
    translator = ProfileTranslator(registry)
    translator.enable_security_checks = true
    
    intent_classifier = IntentClassifier(
        behavioral_threshold = 0.9,  # Stricter for security
        require_consensus = true     # Multiple models must agree
    )
    
    training_regiment = BehavioralTrainingRegiment(
        secure_mode = true,
        validate_inputs = true,
        differential_privacy = true
    )
    
    return ProfileTranslationArchitecture(
        registry = registry,
        translator = translator,
        intent_classifier = intent_classifier,
        training_regiment = training_regiment
    )
end

function add_training_monitors!(dashboard::SecurityDashboard)
    # Monitor training data integrity
    @async while dashboard.watcher.monitoring_active[]
        try
            # Check for anomalous training patterns
            training_files = filter(f -> endswith(f, ".jld2"), 
                                  readdir("data/", join=true))
            
            for file in training_files
                # Verify training data hasn't been tampered with
                if !verify_training_data_integrity(file)
                    violation = FileViolation(
                        file,
                        "expected_signature",
                        "tampered",
                        now(),
                        :critical
                    )
                    handle_violation!(dashboard.watcher, violation)
                end
            end
            
        catch e
            @error "Training monitor error" exception=e
        end
        sleep(10)
    end
end

struct ProfileIntegrityMonitor
    dashboard::SecurityDashboard
    profile_checksums::Dict{String, String}
    change_log::Vector{Dict{String, Any}}
    
    function ProfileIntegrityMonitor(dashboard::SecurityDashboard)
        monitor = new(dashboard, Dict{String, String}(), Vector{Dict{String, Any}}())
        initialize_profile_checksums!(monitor)
        start_profile_monitoring!(monitor)
        return monitor
    end
end

function detect_profile_tampering(monitor::ProfileIntegrityMonitor, code::String)
    # Parse code for profile modifications
    if occursin("save_profile", code) || occursin("profile.", code)
        # Extract profile name and changes
        profile_name = extract_profile_name(code)
        changes = extract_profile_changes(code)
        
        if !isempty(changes)
            return (
                profile_name = profile_name,
                changed_fields = changes,
                severity = :critical
            )
        end
    end
    return nothing
end

function deploy_distributed_security()
    # Setup distributed workers
    addprocs(4)  # Add 4 worker processes
    
    @everywhere using .JuliaMLSecurity
    
    # Create coordinator
    coordinator = DistributedSecurityCoordinator()
    
    # Deploy monitors on each worker
    @sync for worker in workers()
        @async remotecall_wait(worker) do
            local_dashboard = quick_start_security()
            register_with_coordinator(local_dashboard, coordinator)
        end
    end
    
    return coordinator
end

function create_response_playbooks()
    playbooks = Dict{String, ResponsePlaybook}()
    
    # Model extraction attempt playbook
    playbooks["model_extraction"] = ResponsePlaybook(
        name = "Model Extraction Response",
        triggers = ["model_extraction_detected", "excessive_queries"],
        actions = [
            "rate_limit_source",
            "inject_honeypot_responses",
            "alert_security_team",
            "log_query_patterns"
        ],
        escalation_threshold = 100  # queries
    )
    
    # Data poisoning playbook
    playbooks["data_poisoning"] = ResponsePlaybook(
        name = "Data Poisoning Response",
        triggers = ["training_anomaly", "distribution_shift"],
        actions = [
            "pause_training",
            "validate_recent_data",
            "rollback_if_needed",
            "retrain_from_checkpoint"
        ],
        escalation_threshold = 0.15  # 15% anomaly rate
    )
    
    # System intrusion playbook
    playbooks["intrusion"] = ResponsePlaybook(
        name = "System Intrusion Response",
        triggers = ["unauthorized_access", "privilege_escalation"],
        actions = [
            "isolate_affected_systems",
            "terminate_suspicious_processes",
            "collect_forensic_evidence",
            "initiate_incident_response"
        ],
        escalation_threshold = 1  # immediate
    )
    
    return playbooks
end

# Main execution example
function run_all_security_examples()
    println("JuliaML Security System - Comprehensive Examples")
    println("=" ^ 50)
    
    # Run each example
    dashboards = []
    
    push!(dashboards, example_metamorphic_detection())
    push!(dashboards, example_training_poisoning_detection())
    push!(dashboards, example_profile_manipulation())
    push!(dashboards, example_distributed_attack_detection())
    push!(dashboards, example_automated_response())
    
    println("\n" * "=" * 50)
    println("All examples completed. Security dashboards active.")
    println("Access dashboards at: http://localhost:8080")
    
    # Keep running until interrupted
    println("\nPress Ctrl+C to stop all security monitors...")
    
    try
        while true
            sleep(1)
        end
    catch e
        if e isa InterruptException
            println("\nShutting down security monitors...")
            for dashboard in dashboards
                if applicable(dashboard.watcher.monitoring_active)
                    dashboard.watcher.monitoring_active[] = false
                end
            end
        end
    end
end

# Utility function for quick testing
function test_specific_file(filepath::String)
    println("Testing file: $filepath")
    
    dashboard = quick_start_security()
    
    # Comprehensive analysis
    println("\n1. File Integrity Check:")
    hash = compute_file_hash(filepath)
    println("   SHA-256: $hash")
    
    println("\n2. Behavioral Analysis:")
    if endswith(filepath, ".jl")
        analysis = analyze_file_with_ml(dashboard, filepath)
        println("   Risk Score: $(analysis["ml_predictions"]["malicious_score"])")
        println("   Intent: $(analysis["ml_predictions"]["intent"]["intent_type"])")
        
        if analysis["ml_predictions"]["malicious_score"] > 0.5
            println("\n⚠️  WARNING: Suspicious patterns detected!")
            println("   Recommended action: Manual review required")
        end
    end
    
    println("\n3. Real-time Monitoring:")
    println("   File is now being monitored for changes")
    dashboard.watcher.file_integrity_db[filepath] = hash
    
    return dashboard
end

# Export example functions
export run_all_security_examples, test_specific_file
export example_metamorphic_detection, example_training_poisoning_detection
export example_profile_manipulation, example_distributed_attack_detection
export example_automated_response