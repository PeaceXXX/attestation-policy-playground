# Dev policy: anything goes as long as it is labelled dev
# WARNING: never use this policy outside a development sandbox.
package attestation

default allow = false

allow if {
    input.environment == "dev"
    input.workload.image != ""
}

deny["non-dev evidence reached the dev policy"] if {
    input.environment != "dev"
}
