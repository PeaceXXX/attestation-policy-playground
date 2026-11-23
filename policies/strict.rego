# Strict policy: production TDX workloads
package attestation

default allow = false

# Admit only a TDX workload on a current TCB with fresh evidence.
allow if {
    input.platform == "tdx"
    input.tcb.svn >= 5
    input.tcb.status == "up_to_date"
    input.evidence.age_seconds < 300
    input.measurements.mrtd != "0000000000000000000000000000000000000000000000000000000000000000"
    count(input.measurements.allowed) >= 1
}

deny["TCB SVN is below the minimum (5)"] if {
    input.tcb.svn < 5
}

deny["TCB status is not up_to_date"] if {
    input.tcb.status != "up_to_date"
}

deny["evidence is stale: older than 300 seconds"] if {
    input.evidence.age_seconds >= 300
}

deny["workload is not running on TDX"] if {
    input.platform != "tdx"
}

deny[msg] if {
    input.measurements.mrtd == "0000000000000000000000000000000000000000000000000000000000000000"
    msg := "MRTD is all zeros; the measurement was never populated"
}

deny["debug mode must never reach production"] if {
    input.debug == true
}
