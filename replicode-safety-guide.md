# Replicode Security Integration - Safety Guide & Best Practices

## ⚠️ CRITICAL SAFETY INFORMATION

The replicode executable has the power to **permanently destroy source code**. This integration includes multiple safety mechanisms to prevent accidental destruction, but extreme caution is still required.

## Safety Features

### 1. **Safety Mode (Default: ON)**
- When enabled, ALL destruction operations are blocked
- Must be explicitly disabled for each destruction session
- Automatically re-enables after operations

### 2. **Destruction Whitelist**
- Only files explicitly added to whitelist can be destroyed
- Whitelist is cleared after successful destruction
- Prevents accidental destruction of system files

### 3. **Authentication Tokens**
- Unique token required for each destruction operation
- Tokens are session-specific and expire
- Prevents unauthorized destruction attempts

### 4. **Mandatory Backups**
- Automatic backup before ANY replicode operation
- Backups stored in quarantine directory
- Multiple redundant copies for destruction operations

### 5. **Multi-Level Confirmation**
- Text confirmation required ("DESTROY", "CONFIRM DESTRUCTION")
- Auth token verification
- Manual safety mode disable

## Quick Start

```julia
# Initialize with your replicode executable path
security = initialize_replicode_security(
    replicode_path = "/path/to/replicode"
)

# System starts in SAFE MODE - only analysis allowed
# Destruction operations will fail unless explicitly authorized
```

## Safe Usage Patterns

### Analyzing Files (Safe Operation)

```julia
# Single file analysis - completely safe
analysis = analyze_suspicious_julia_file("suspicious.jl", security.replicode)

# Batch analysis - safe, read-only operation
high_risk_files = batch_analyze_with_progress("src/", security.replicode)
```

### Compilation (Safe Operation)

```julia
# Compile code safely
result = replicode_compile(
    security.replicode.replicode,
    source_code,
    output_file = "compiled_output.bin"
)
```

### Destruction (Dangerous Operation)

```julia
# ONLY use the safe workflow with all protections
safe_destruction_workflow("malicious_file.jl", security.replicode)

# This will:
# 1. Analyze the file first
# 2. Create multiple backups
# 3. Require manual authorization
# 4. Require auth token
# 5. Re-enable safety mode after
```

## Best Practices

### 1. **Always Start in Safety Mode**
```julia
# ✓ CORRECT - Default safe configuration
integration = ReplicodeSecurityIntegration(exe_path, monitor)

# ✗ WRONG - Never start with safety disabled
integration.replicode.safety_mode = false  # DON'T DO THIS!
```

### 2. **Use Automated Analysis First**
```julia
# Let the system analyze violations automatically
integration.auto_decompile = true
integration.risk_threshold = 0.7  # Only quarantine high-risk files
```

### 3. **Verify Replicode Executable**
```julia
# The system verifies the executable hash
# Update KNOWN_REPLICODE_HASH in the code with your executable's SHA-256
KNOWN_REPLICODE_HASH = sha256(read("/path/to/replicode"))
```

### 4. **Monitor Operation Logs**
```julia
# Check what replicode has been doing
for op in security.replicode.replicode.operation_log
    println("$(op.timestamp): $(op.operation) on $(op.target)")
end
```

### 5. **Set Resource Limits**
- Replicode operations have 30-second timeout
- Rate limiting prevents system overload
- Quarantine directory size should be monitored

## Configuration File

Create `replicode_config.yaml`:

```yaml
# Replicode Security Configuration
replicode:
  executable_path: /path/to/replicode
  safety_mode: true  # ALWAYS true in config
  
  # Analysis settings
  auto_decompile: true
  decompile_timeout: 30
  
  # Risk thresholds
  quarantine_threshold: 0.7
  alert_threshold: 0.5
  destruction_threshold: 0.95  # Only highest risk
  
  # Backup settings
  backup_before_analysis: true
  backup_retention_days: 30
  max_backup_size_gb: 100

# Monitoring paths
monitor_paths:
  - src/
  - models/
  - data/

# Critical files that should NEVER be destroyed
protected_files:
  - ModuleProfileRegistry.jl
  - ProfileTranslationArchitecture.jl
  - BehavioralTrainingRegiment.jl
```

## Emergency Procedures

### If Accidental Destruction Occurs

1. **Check quarantine directory for backups**
   ```julia
   backups = readdir(security.replicode.replicode.quarantine_directory)
   ```

2. **Restore from backup**
   ```julia
   cp(backup_path, original_path)
   ```

3. **Review operation log**
   ```julia
   destruction_ops = filter(op -> op.operation == :destroy, 
                           security.replicode.replicode.operation_log)
   ```

### If System Compromise Suspected

1. **Enable Emergency Mode**
   ```julia
   # This requires multiple confirmations
   emergency_destruction_protocol!(
       security.replicode,
       confirmed_malicious_files,
       "Critical system compromise"
   )
   ```

2. **Isolate System**
   - Disconnect network
   - Stop all Julia processes
   - Preserve logs for analysis

## Monitoring & Alerts

### Dashboard Endpoints

- Main Dashboard: `http://localhost:8080`
- Replicode Stats: `http://localhost:8080/api/replicode/stats`
- Operation History: `http://localhost:8080/api/replicode/operations`
- Violation Log: `http://localhost:8080/api/violations`

### Key Metrics to Monitor

1. **Decompilation Rate** - Sudden spikes may indicate attack
2. **Risk Score Distribution** - Many high-risk files = problem
3. **Quarantine Size** - Growing rapidly = active threat
4. **Failed Operations** - May indicate tampering

## Integration with ML System

The replicode analysis integrates with your juliaML behavioral learning:

1. **Behavioral Pattern Extraction** - Replicode identifies code patterns
2. **ML Classification** - Patterns fed to IntentClassifier
3. **Risk Assessment** - Combined replicode + ML risk scoring
4. **Automated Response** - Based on both analyses

## Troubleshooting

### "Replicode executable not found"
- Verify path in configuration
- Check file permissions (must be executable)
- Ensure hash matches expected value

### "Destruction failed - not whitelisted"
- File must be explicitly added to whitelist
- Check `security.replicode.replicode.destruction_whitelist`
- Whitelist cleared after destruction

### "Invalid auth token"
- Tokens are session-specific
- Get current token: `security.replicode.replicode.auth_token`
- Tokens cannot be reused

### High Memory Usage
- Replicode operations can be memory-intensive
- Adjust batch size for analysis
- Increase rate limiting delays

## Security Considerations

1. **Protect the Replicode Executable**
   - Store in read-only location
   - Monitor for modifications
   - Regularly verify hash

2. **Audit All Destructions**
   - Review operation logs daily
   - Investigate any unexpected destructions
   - Maintain backup retention policy

3. **Limit Access**
   - Restrict who can disable safety mode
   - Use environment variables for auth tokens
   - Log all configuration changes

4. **Regular Testing**
   - Test destruction workflow on dummy files
   - Verify backup restoration process
   - Check alert systems monthly

## Support

For issues or questions:
1. Check operation logs first
2. Review this safety guide
3. Test with non-critical files
4. Always maintain backups

Remember: **When in doubt, don't destroy!**