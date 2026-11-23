# Standard policy: TDX or SEV-SNP, moderate freshness bar
package attestation

default allow = false

allow if {
    input.platform in ["tdx", "sev-snp"]
    input.tcb.svn >= 3
    input.evidence.age_seconds < 900
    input.measurements.mrtd != "0000000000000000000000000000000000000000000000000000000000000000"
}

deny["TCB SVN is below the minimum (3)"] if {
    input.tcb.svn < 3
}

deny["evidence is stale: older than 900 seconds"] if {
    input.evidence.age_seconds >= 900
}

deny[msg] if {
    input.measurements.mrtd == "0000000000000000000000000000000000000000000000000000000000000000"
    msg := "MRTD is all zeros; the measurement was never populated"
}
