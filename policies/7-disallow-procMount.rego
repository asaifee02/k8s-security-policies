# METADATA
# scope: package
# title: Disallow procMount
# description: This policy ensures nothing but the default procMount can be specified.
# related_resources:
# - ref: https://kyverno.io/policies/pod-security/baseline/disallow-proc-mount/disallow-proc-mount/
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
  check1 := { c | p := input.request.object.spec.containers[i].securityContext.procMount; p != "Default"; c := input.request.object.spec.containers[i].name }
  check2 := { c | p := input.request.object.spec.initContainers[i].securityContext.procMount; p != "Default"; c := input.request.object.spec.initContainers[i].name }
  check := check1 | check2
  count(check) > 0
  page := "https://learningcicd.github.io/7-disallow-procmount.html"
  msg := sprintf("Changing the procMount from the default is not allowed. The field 'securityContext.procMount' for the containers '[%s]' must either be unset or set to 'Default'. For more information, please visit %s.", [concat(", ", check), page])
}
