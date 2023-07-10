# METADATA
# scope: package
# title: Disallow SELinux
# description: This policy ensures that the `seLinuxOptions` field is undefined.
# related_resources:
# - ref: https://kyverno.io/policies/pod-security/baseline/disallow-selinux/disallow-selinux/
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
  count(input.request.object.spec.securityContext.seLinuxOptions.user) > 0
  page := "https://learningcicd.github.io/8-disallow-selinux.html"
  msg := sprintf("Setting the SELinux user is forbidden. The field 'spec.securityContext.seLinuxOptions.user' must be unset.", [page])
}

match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
  input.request.kind.kind == "Pod"
  check1 := { c | p := input.request.object.spec.containers[i].securityContext.seLinuxOptions.user; count(p) > 0; c := input.request.object.spec.containers[i].name }
  check2 := { c | p := input.request.object.spec.initContainers[i].securityContext.seLinuxOptions.user; count(p) > 0; c := input.request.object.spec.initContainers[i].name }
  check := check1 | check2
  count(check) > 0
  page := "https://learningcicd.github.io/8-disallow-selinux.html"
  msg := sprintf("Setting the SELinux user is forbidden. The field 'securityContext.seLinuxOptions.user' must be unset for the containers '[%s]'. For more information, please visit %s.", [concat(", ", check), page])
}

match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
  input.request.kind.kind == "Pod"
  count(input.request.object.spec.securityContext.seLinuxOptions.role) > 0
  page := "https://learningcicd.github.io/8-disallow-selinux.html"
  msg := sprintf("Setting the SELinux role is forbidden. The field 'spec.securityContext.seLinuxOptions.role' must be unset. For more information, please visit %s.", [page])
}

match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
  input.request.kind.kind == "Pod"
  check1 := { c | p := input.request.object.spec.containers[i].securityContext.seLinuxOptions.role; count(p) > 0; c := input.request.object.spec.containers[i].name }
  check2 := { c | p := input.request.object.spec.initContainers[i].securityContext.seLinuxOptions.role; count(p) > 0; c := input.request.object.spec.initContainers[i].name }
  check := check1 | check2
  count(check) > 0
  page := "https://learningcicd.github.io/8-disallow-selinux.html"
  msg := sprintf("Setting the SELinux role is forbidden. The field 'securityContext.seLinuxOptions.role' must be unset for the containers '[%s]'. For more information, please visit %s.", [concat(", ", check), page])
}

match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
  input.request.kind.kind == "Pod"
  allowed := {"", "container_t", "container_init_t", "container_kvm_t"}
  not allowed[input.request.object.spec.securityContext.seLinuxOptions.type]
  page := "https://learningcicd.github.io/8-disallow-selinux.html"
  msg := sprintf("Setting the SELinux type is restricted. The field 'spec.securityContext.seLinuxOptions.type' must either be unset or set to one of the allowed values (container_t, container_init_t, or container_kvm_t). For more information, please visit %s.", [page])
}

match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
  input.request.kind.kind == "Pod"
  allowed := {"", "container_t", "container_init_t", "container_kvm_t"}
  check1 := { c | p := input.request.object.spec.containers[i].securityContext.seLinuxOptions.type; not allowed[p]; c := input.request.object.spec.containers[i].name }
  check2 := { c | p := input.request.object.spec.initContainers[i].securityContext.seLinuxOptions.type; not allowed[p]; c := input.request.object.spec.initContainers[i].name }
  check := check1 | check2
  count(check) > 0
  page := "https://learningcicd.github.io/8-disallow-selinux.html"
  msg := sprintf("Setting the SELinux type is restricted. The field 'securityContext.seLinuxOptions.type' for the containers '[%s]' must either be unset or set to one of the allowed values (container_t, container_init_t, or container_kvm_t). For more information, please visit %s.", [concat(", ", check), page])
}
