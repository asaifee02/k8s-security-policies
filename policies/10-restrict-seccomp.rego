# METADATA
# scope: package
# title: Restrict Seccomp
# description: This policy, requiring Kubernetes v1.19 or later, ensures that seccomp is unset or set to `RuntimeDefault` or `Localhost`.
# related_resources:
# - ref: https://kyverno.io/policies/pod-security/baseline/restrict-seccomp/restrict-seccomp/
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
  allowed := {"", "RuntimeDefault", "Localhost"}
  not allowed[input.request.object.spec.securityContext.seccompProfile.type]
  page := "https://learningcicd.github.io/10-restrict-seccomp.html"
  msg := sprintf("Use of custom Seccomp profiles is disallowed. The field 'spec.securityContext.seccompProfile.type' must either be unset or set to 'RuntimeDefault' or 'Localhost'. For more information, please visit %s.", [page])
}

match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
  input.request.kind.kind == "Pod"
  allowed := {"", "RuntimeDefault", "Localhost"}
  check1 := { c | p := input.request.object.spec.containers[i].securityContext.seccompProfile.type; not allowed[p]; c := input.request.object.spec.containers[i].name }
  check2 := { c | p := input.request.object.spec.initContainers[i].securityContext.seccompProfile.type; not allowed[p]; c := input.request.object.spec.initContainers[i].name }
  check := check1 | check2
  count(check) > 0
  page := "https://learningcicd.github.io/10-restrict-seccomp.html"
  msg := sprintf("Use of custom Seccomp profiles is disallowed. The field 'securityContext.seccompProfile.type' for the containers '[%s]' must either be unset or set to 'RuntimeDefault' or 'Localhost'. For more information, please visit %s.", [concat(", ", check), page])
}
