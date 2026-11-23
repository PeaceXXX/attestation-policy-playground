# GPU workload policy: composite CPU + GPU attestation
# The workload is admitted only when BOTH the TDX CPU claim and the
# GPU claim are present, current, and bound to the same job.
package attestation

default allow = false

allow if {
    input.platform == "tdx"
    input.tcb.svn >= 5
    input.evidence.age_seconds < 300
    input.gpu.present == true
    input.gpu.attested == true
    input.gpu.driver_svn >= 2
    input.gpu.job_id == input.workload.job_id
    startswith(input.workload.image, "ghcr.io/peacexxx/")
}

deny["GPU claim is missing or not attested"] if {
    input.gpu.attested != true
}

deny["GPU driver SVN is below the minimum (2)"] if {
    input.gpu.driver_svn < 2
}

deny["GPU claim is bound to a different job than the workload"] if {
    input.gpu.job_id != input.workload.job_id
}

deny["workload image is not from the trusted registry"] if {
    not startswith(input.workload.image, "ghcr.io/peacexxx/")
}
