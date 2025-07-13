# Complete Replicode Integration Example
# Safe usage patterns and monitoring setup

include("SecurityMonitor.jl")
include("ReplicodeWrapper.jl")
include("MLIntegration.jl")

# Configuration for replicode integration
const REPLICODE_CONFIG = Dict(
    "executable_path" => "/path/to/your/replicode",  # Update this!
    "safety_mode" => true,  # Always start in safety mode
    "auto_decompile_threshold" => 0.6,
    "auto_quarantine_threshold" => 0.8,
    "destruction_requires_votes" => 3,  # Multiple confirmations needed
    "backup_before_analysis" => true
)

# Initialize complete security system with replicode
function initialize_replicode_security(;
    replicode_path::String = REPLICODE_CONFIG["executable_path"],
    ml_architecture = nothing
)
    @info "Initializing JuliaML Security with Replicode Integration"
    
    # Step 1: Verify replicode executable
    if !isfile(replicode_path)
        error("""
        Replicode executable not found at: $replicode_path
        Please update REPLICODE_CONFIG["executable_path"] with the correct path.
        """)
    end
    
    # Step 2: Create ML architecture if not provided
    if ml_architecture === nothing
        ml_architecture = create_secure_ml_architecture()
    end
    
    # Step 3: Initialize base security monitor
    security_monitor = initialize_security_monitor(
        monitor_paths = ["src/", "models/", "data/"],
        whitelisted_processes = ["julia", "replicode"],
        network_rules = [
            conn -> conn.port in [6666, 31337],  # Known backdoor ports
            conn -> !startswith(conn.destination_ip, "192.168.")  # External connections
        ]
    )
    
    # Step 4: Create replicode integration
    replicode_integration = ReplicodeSecurityIntegration(
        replicode_path,
        security_monitor
    )
    
    # Configure replicode settings
    replicode_integration.auto_decompile = true
    replicode_integration.auto_quarantine = true
    replicode_integration.risk_threshold = REPLICODE_CONFIG["auto_quarantine_threshold"]
    
    # Step 5: Setup automated violation handling
    @async monitor_violations_with_replicode(replicode_integration)
    
    # Step 6: Create integrated dashboard
    dashboard = create_integrated_dashboard(
        security_monitor,
        replicode_integration,
        ml_architecture
    )
    
    @info """
    Replicode Security System Initialized
    - Executable: $replicode_path
    - Safety Mode: $(replicode_integration.replicode.safety_mode)
    - Auto Decompile: $(replicode_integration.auto_decompile)
    - Dashboard: http://localhost:8080
    """
    
    return (
        monitor = security_monitor,
        replicode = replicode_integration,
        dashboard = dashboard
    )
end

# Monitor violations and auto-analyze with replicode
function monitor_violations_with_replicode(integration::ReplicodeSecurityIntegration)
    @info "Starting replicode violation monitor"
    
    while integration.security_monitor.monitoring_active[]
        try
            # Check for new violations
            if !isempty(integration.security_monitor.alerts_channel)
                violation = take!(integration.security_monitor.alerts_channel)
                
                # Analyze with replicode
                analysis = auto_analyze_violation!(integration, violation)
                
                if analysis !== nothing
                    # Log detailed analysis
                    log_replicode_analysis(analysis, violation)
                    
                    # Check if ML models need updating
                    if should_update_ml_models(analysis)
                        update_ml_from_replicode_analysis(integration, analysis)
                    end
                end
            end
            
            sleep(0.5)
        catch e
            @error "Replicode monitor error" exception=e
        end
    end
end

# Example: Analyzing a suspicious Julia file
function analyze_suspicious_julia_file(filepath::String, integration::ReplicodeSecurityIntegration)
    println("\n=== Replicode Analysis of: $filepath ===")
    
    # Create backup first
    backup_path = backup_before_analysis(filepath)
    println("✓ Backup created: $backup_path")
    
    # Perform decompilation
    println("→ Starting replicode decompilation...")
    analysis = replicode_decompile(
        integration.replicode,
        filepath,
        initiated_by = "ManualAnalysis"
    )
    
    # Display results
    println("\nSecurity Analysis Results:")
    println("- Overall Risk Score: $(round(analysis["overall_risk"] * 100, digits=1))%")
    
    if !isempty(analysis["security_flags"])
        println("- Security Flags Detected:")
        for flag in analysis["security_flags"]
            println("  ⚠️  $flag")
        end
    end
    
    if !isempty(analysis["behavioral_patterns"])
        println("- Behavioral Patterns:")
        for (pattern, data) in analysis["behavioral_patterns"]
            println("  • $pattern: $data")
        end
    end
    
    # Risk assessment
    println("\nRisk Assessment:")
    for (risk_type, score) in analysis["risk_assessment"]
        risk_level = score > 0.8 ? "CRITICAL" : score > 0.6 ? "HIGH" : score > 0.4 ? "MEDIUM" : "LOW"
        println("  - $risk_type: $risk_level ($(round(score * 100, digits=1))%)")
    end
    
    # Recommendations
    if analysis["overall_risk"] >= 0.9
        println("\n🚨 CRITICAL RISK - Immediate action recommended:")
        println("1. Quarantine file immediately")
        println("2. Investigate source and related files")
        println("3. Consider adding to destruction whitelist")
    elseif analysis["overall_risk"] >= 0.7
        println("\n⚠️  HIGH RISK - Recommended actions:")
        println("1. Move to quarantine for further analysis")
        println("2. Run behavioral sandbox testing")
        println("3. Check for similar patterns in other files")
    else
        println("\n✓ File appears relatively safe (risk < 70%)")
    end
    
    return analysis
end

# Example: Batch analysis with progress tracking
function batch_analyze_with_progress(directory::String, integration::ReplicodeSecurityIntegration)
    println("\n=== Batch Replicode Analysis ===")
    println("Directory: $directory")
    
    # Count files first
    total_files = 0
    for (root, dirs, files) in walkdir(directory)
        total_files += count(f -> is_potentially_executable(joinpath(root, f)), files)
    end
    
    println("Found $total_files potentially executable files")
    print("Proceed with analysis? (y/n): ")
    
    if readline() != "y"
        println("Analysis cancelled")
        return
    end
    
    # Perform analysis with progress
    analyzed = 0
    high_risk_files = String[]
    
    for (root, dirs, files) in walkdir(directory)
        for file in files
            filepath = joinpath(root, file)
            
            if !is_potentially_executable(filepath)
                continue
            end
            
            analyzed += 1
            print("\rAnalyzing: $analyzed/$total_files ($(round(analyzed/total_files * 100, digits=1))%)")
            
            try
                analysis = replicode_decompile(
                    integration.replicode,
                    filepath,
                    initiated_by = "BatchAnalysis"
                )
                
                if analysis["overall_risk"] >= 0.7
                    push!(high_risk_files, filepath)
                end
                
            catch e
                # Log but continue
                @debug "Failed to analyze" file=filepath error=e
            end
            
            # Rate limiting
            sleep(0.05)
        end
    end
    
    println("\n\nAnalysis Complete!")
    println("- Total files analyzed: $analyzed")
    println("- High risk files found: $(length(high_risk_files))")
    
    if !isempty(high_risk_files)
        println("\nHigh Risk Files:")
        for (i, file) in enumerate(high_risk_files)
            println("  $i. $file")
        end
        
        println("\nWould you like to quarantine all high-risk files? (y/n): ")
        if readline() == "y"
            quarantine_files(high_risk_files, integration)
        end
    end
    
    return high_risk_files
end

# Safe destruction example with multiple safeguards
function safe_destruction_workflow(filepath::String, integration::ReplicodeSecurityIntegration)
    println("\n=== Safe Destruction Workflow ===")
    println("Target: $filepath")
    
    # Step 1: Analyze first
    println("\nStep 1: Analyzing file...")
    analysis = replicode_decompile(integration.replicode, filepath)
    
    if analysis["overall_risk"] < 0.95
        println("⚠️  File risk score is below critical threshold (95%)")
        println("Risk score: $(round(analysis["overall_risk"] * 100, digits=1))%")
        print("Continue with destruction anyway? (yes/no): ")
        
        if readline() != "yes"
            println("Destruction cancelled")
            return
        end
    end
    
    # Step 2: Create multiple backups
    println("\nStep 2: Creating backups...")
    backups = create_redundant_backups(filepath, 3)
    println("✓ Created $(length(backups)) backup copies")
    
    # Step 3: Get authorization
    println("\nStep 3: Authorization required")
    println("This action requires disabling safety mode and will PERMANENTLY destroy:")
    println("  $filepath")
    
    print("\nEnter 'AUTHORIZE DESTRUCTION' to proceed: ")
    if readline() != "AUTHORIZE DESTRUCTION"
        println("Authorization failed - destruction cancelled")
        return
    end
    
    # Step 4: Disable safety and whitelist file
    println("\nStep 4: Preparing for destruction...")
    integration.replicode.safety_mode = false
    push!(integration.replicode.destruction_whitelist, filepath)
    
    # Step 5: Final confirmation with auth token
    auth_token = integration.replicode.auth_token
    println("\nStep 5: Final confirmation")
    println("Auth token: $auth_token")
    print("Enter auth token to destroy file: ")
    
    entered_token = readline()
    
    if entered_token == auth_token
        # Proceed with destruction
        result = replicode_destroy!(
            integration.replicode,
            filepath,
            auth_token = auth_token,
            reason = "Authorized destruction after analysis",
            initiated_by = "SafeDestructionWorkflow"
        )
        
        if result.success
            println("\n✓ File successfully destroyed")
            println("  Backup available at: $(result.backup_path)")
        else
            println("\n✗ Destruction failed: $(result.log)")
        end
    else
        println("\n✗ Invalid token - destruction cancelled")
    end
    
    # Always re-enable safety mode
    integration.replicode.safety_mode = true
    
    println("\nSafety mode re-enabled")
end

# Integrated dashboard with replicode stats
function create_integrated_dashboard(monitor::SystemWatcher, 
                                   replicode_integration::ReplicodeSecurityIntegration,
                                   ml_arch)
    dashboard = SecurityDashboard(monitor, ml_arch)
    
    # Add replicode-specific endpoints
    HTTP.@register(dashboard.web_server.router, "GET", "/api/replicode/stats", req -> begin
        stats = Dict(
            "total_operations" => length(replicode_integration.replicode.operation_log),
            "decompilations" => count(op -> op.operation == :decompile, 
                                     replicode_integration.replicode.operation_log),
            "compilations" => count(op -> op.operation == :compile,
                                   replicode_integration.replicode.operation_log),
            "destructions" => count(op -> op.operation == :destroy,
                                   replicode_integration.replicode.operation_log),
            "safety_mode" => replicode_integration.replicode.safety_mode,
            "auto_decompile" => replicode_integration.auto_decompile,
            "quarantine_count" => length(readdir(replicode_integration.replicode.quarantine_directory))
        )
        JSON3.write(stats)
    end)
    
    HTTP.@register(dashboard.web_server.router, "GET", "/api/replicode/operations", req -> begin
        # Return recent operations
        recent_ops = replicode_integration.replicode.operation_log[end-min(50, end):end]
        JSON3.write(map(op -> Dict(
            "timestamp" => op.timestamp,
            "operation" => string(op.operation),
            "target" => basename(op.target),
            "success" => op.success,
            "initiated_by" => op.initiated_by
        ), recent_ops))
    end)
    
    # Start dashboard
    start_security_dashboard(dashboard, port=8080)
    
    return dashboard
end

# Helper functions
function backup_before_analysis(filepath::String)
    backup_dir = mkpath("backups/pre_analysis")
    backup_path = joinpath(backup_dir, "$(now())_$(basename(filepath))")
    cp(filepath, backup_path)
    return backup_path
end

function create_redundant_backups(filepath::String, count::Int)
    backups = String[]
    
    for i in 1:count
        backup_dir = mkpath("backups/destruction/copy_$i")
        backup_path = joinpath(backup_dir, "$(now())_$(basename(filepath))")
        cp(filepath, backup_path)
        push!(backups, backup_path)
    end
    
    return backups
end

function quarantine_files(files::Vector{String}, integration::ReplicodeSecurityIntegration)
    quarantined = 0
    
    for file in files
        try
            quarantine_path = joinpath(
                integration.replicode.quarantine_directory,
                "batch_$(now())_$(basename(file))"
            )
            mv(file, quarantine_path, force=true)
            quarantined += 1
            @info "Quarantined" file=file destination=quarantine_path
        catch e
            @error "Failed to quarantine" file=file error=e
        end
    end
    
    println("\n✓ Quarantined $quarantined/$(length(files)) files")
end

function log_replicode_analysis(analysis::Dict, violation::ViolationType)
    # Create detailed log entry
    log_entry = Dict(
        "timestamp" => now(),
        "violation_type" => string(typeof(violation)),
        "violation_details" => violation,
        "replicode_analysis" => analysis,
        "action_taken" => "auto_analyzed"
    )
    
    # Write to dedicated replicode log
    open("replicode_analysis.jsonl", "a") do f
        println(f, JSON3.write(log_entry))
    end
end

# Main execution example
function demo_replicode_security()
    println("JuliaML Replicode Security Integration Demo")
    println("=" ^ 50)
    
    # Initialize system
    security_system = initialize_replicode_security()
    
    # Example 1: Analyze a specific file
    println("\nExample 1: Analyzing a single file")
    if isfile("example_suspicious.jl")
        analyze_suspicious_julia_file("example_suspicious.jl", security_system.replicode)
    else
        println("(Skipped - no example file found)")
    end
    
    # Example 2: Batch analysis
    println("\nExample 2: Batch analysis of src/ directory")
    print("Run batch analysis? (y/n): ")
    if readline() == "y"
        batch_analyze_with_progress("src/", security_system.replicode)
    end
    
    # Example 3: Monitor real-time
    println("\nExample 3: Real-time monitoring active")
    println("Dashboard available at: http://localhost:8080")
    println("Replicode stats at: http://localhost:8080/api/replicode/stats")
    
    println("\nSystem is now monitoring. Press Ctrl+C to stop.")
    
    # Keep running
    try
        while true
            sleep(1)
        end
    catch e
        if e isa InterruptException
            println("\nShutting down security system...")
            security_system.monitor.monitoring_active[] = false
        end
    end
end

# Export main functions
export initialize_replicode_security, analyze_suspicious_julia_file
export batch_analyze_with_progress, safe_destruction_workflow
export demo_replicode_security