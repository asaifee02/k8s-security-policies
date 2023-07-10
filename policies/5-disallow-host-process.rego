# METADATA
# scope: package
# title: Disallow hostProcess
# description: This policy ensures the `hostProcess` field, if present, is set to `false`.
# related_resources:
# - ref: https://kyverno.io/policies/pod-security/baseline/disallow-host-process/disallow-host-process/
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
  host1 := { c | h := input.request.object.spec.containers[i].securityContext.windowsOptions.hostProcess; h; c := input.request.object.spec.containers[i].name }
  host2 := { c | h := input.request.object.spec.initContainers[i].securityContext.windowsOptions.hostProcess; h; c := input.request.object.spec.initContainers[i].name }
  host := host1 | host2
  count(host) > 0
  page := "https://learningcicd.github.io/5-disallow-hostprocess.html"
  msg := sprintf("HostProcess containers are disallowed. The field 'securityContext.windowsOptions.hostProcess' for the containers '[%s]' must either be unset or set to 'false'. For more information, please visit %s.", [concat(", ", host), page])
}

match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
  input.request.kind.kind == "Pod"
  input.request.object.spec.securityContext.windowsOptions.hostProcess
  page := "https://learningcicd.github.io/5-disallow-hostprocess.html"
  msg := sprintf("HostProcess containers are disallowed. The field 'spec.securityContext.windowsOptions.hostProcess' must either be unset or set to 'false'. For more information, please visit %s.", [page])
}