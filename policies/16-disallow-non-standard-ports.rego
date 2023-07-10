# METADATA
# scope: package
# title: Disallow Non-Standard Ports
# description: This policy ensures that every container in a pod only exposes the standard port (443).
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
  allowed := { 443 }
  check1 := { p | p := input.request.object.spec.containers[_].ports[_].containerPort }
  check2 := { p | p := input.request.object.spec.initContainers[_].ports[_].containerPort }
  ports := check1 | check2
  check := ports - allowed
  count(check) > 0
  page := "https://learningcicd.github.io/16-disallow-non-standard-ports.html"
  msg := sprintf("Non-standard containerPorts are disallowed. The containerPorts '[%s]' must be unset or set to '443'. For more information, please visit %s.", [check, page])
}
