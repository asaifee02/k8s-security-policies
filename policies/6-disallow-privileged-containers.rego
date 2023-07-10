# METADATA
# scope: package
# title: Disallow Privileged Containers
# description: This policy ensures Pods do not call for privileged mode.
# related_resources:
# - ref: https://kyverno.io/policies/pod-security/baseline/disallow-privileged-containers/disallow-privileged-containers/
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
  check1 := { c | p := input.request.object.spec.containers[i].securityContext.privileged; p; c := input.request.object.spec.containers[i].name }
  check2 := { c | p := input.request.object.spec.initContainers[i].securityContext.privileged; p; c := input.request.object.spec.initContainers[i].name }
  check := check1 | check2
  count(check) > 0
  page := "https://learningcicd.github.io/6-disallow-privileged-containers.html"
  msg := sprintf("Privileged mode is disallowed. The field 'securityContext.privileged' for the containers '[%s]' must either be unset or set to 'false'. For more information, please visit %s.", [concat(", ", check), page])
}
