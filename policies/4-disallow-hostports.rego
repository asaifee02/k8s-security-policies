# METADATA
# scope: package
# title: Disallow hostPorts
# description: This policy ensures that `ports.hostPort` for all containers is either unset or set to 0.
# related_resources:
# - ref: https://kyverno.io/policies/pod-security/baseline/disallow-host-ports/disallow-host-ports/
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
  ports1 := { p | p := input.request.object.spec.containers[_].ports[_].hostPort; p != 0 }
  ports2 := { p | p := input.request.object.spec.initContainers[_].ports[_].hostPort; p != 0 }
  ports := ports1 | ports2
  count(ports) > 0
  page := "https://learningcicd.github.io/4-disallow-hostports.html"
  msg := sprintf("Use of host ports is disallowed. The hostPorts '%v' must be unset or set to '0'. For more information, please visit %s.", [ports, page])
}
