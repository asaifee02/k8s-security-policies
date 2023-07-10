# METADATA
# scope: package
# title: Disallow hostPath
# description: This policy ensures no hostPath volumes (spec.volumes[*].hostPath) are in use.
# related_resources:
# - ref: https://kyverno.io/policies/pod-security/baseline/disallow-host-path/disallow-host-path/
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
  input.request.object.spec.volumes[_].hostPath
  page := "https://learningcicd.github.io/3-disallow-hostpath.html"
  msg := sprintf("HostPath volumes are forbidden. The field 'spec.volumes[*].hostPath' must be unset. For more information, please visit %s.", [page])
}
