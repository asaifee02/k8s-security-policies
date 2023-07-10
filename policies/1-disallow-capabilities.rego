# METADATA
# scope: package
# title: Disallow Capabilities
# description: This policy ensures that adding capabilities beyond those listed in the policy will be disallowed.
# related_resources:
# - ref: https://kyverno.io/policies/pod-security/baseline/disallow-capabilities/disallow-capabilities/
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
  caps1 := { x | x := input.request.object.spec.containers[_].securityContext.capabilities.add[_] }
  caps2 := { x | x := input.request.object.spec.initContainers[_].securityContext.capabilities.add[_] }
  caps := caps1 | caps2
  allowed := {"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"}
  disallowed := caps - allowed
  count(disallowed) > 0
  page := "https://learningcicd.github.io/1-disallow-capabilities.html"
  msg := sprintf("Capabilities '%v' are not allowed. For more information, please visit %s.", [disallowed, page])
}
