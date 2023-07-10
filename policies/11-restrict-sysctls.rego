# METADATA
# scope: package
# title: Restrict sysctls
# description: This policy ensures that only those "safe" subsets can be specified in a Pod.
# related_resources:
# - ref: https://kyverno.io/policies/pod-security/baseline/restrict-sysctls/restrict-sysctls/
# authors:
# - name: Adnan Saifee
#   email: asaifee02@gmail.com
# schemas: 
#   - input: schema["input"]
#   - input.request.object: schema.kubernetes["pod"]
package kubernetes.policies

match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
  input.request.kind.kind == "Pod"
  sysctls := { x | x := input.request.object.spec.securityContext.sysctls[_].name }
  allowed := { "kernel.shm_rmid_forced", "net.ipv4.ip_local_port_range", "net.ipv4.ip_unprivileged_port_start", "net.ipv4.tcp_syncookies", "net.ipv4.ping_group_range" }
  disallowed := sysctls - allowed
  count(disallowed) > 0
  page := "https://learningcicd.github.io/11-restrict-sysctls.html"
  msg := sprintf("Setting additional sysctls above the allowed type is disallowed. Please unset the sysctls '%v'. The field 'spec.securityContext.sysctls' must be unset or set to the allowed names. For more information, please visit %s.", [disallowed, page])
}