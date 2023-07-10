# METADATA
# scope: package
# title: Disallow Host Namespaces
# description: This policy ensures fields which make use of these host namespaces (spec.hostNetwork, spec.hostIPC, and spec.hostPID) are unset or set to false.
# related_resources:
# - ref: https://kyverno.io/policies/pod-security/baseline/disallow-host-namespaces/disallow-host-namespaces/
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
	input.request.object.spec.hostNetwork
  page := "https://learningcicd.github.io/2-disallow-host-namespaces.html"
  msg := sprintf("The field 'spec.hostNetwork' must be unset or set to 'false'. For more information, please visit %s.", [page])
}

match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
	input.request.kind.kind == "Pod"
  input.request.object.spec.hostIPC
  page := "https://learningcicd.github.io/2-disallow-host-namespaces.html"
  msg := sprintf("The field 'spec.hostIPC' must be unset or set to 'false'. For more information, please visit %s.", [page])
}

match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
	input.request.kind.kind == "Pod"
  input.request.object.spec.hostPID
  page := "https://learningcicd.github.io/2-disallow-host-namespaces.html"
  msg := sprintf("The field 'spec.hostPID' must be unset or set to 'false'. For more information, please visit %s.", [page])
}
