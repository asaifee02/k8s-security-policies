# METADATA
# scope: package
# title: Disallow Pods without Probes
# description: This policy ensures that every container of a pod has readinessProbe and livenessProbe configurations.
# related_resources:
# - ref: https://github.com/redhat-cop/rego-policies/blob/master/POLICIES.md#rhcop-ocp_bestpract-00009-container-readiness-prob-is-not-set
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
  name := input.request.object.metadata.name
  container := input.request.object.spec.containers
  initContainer := input.request.object.spec.initContainers
  check1 := { c | not container[i].readinessProbe; c := container[i].name }
  check2 := { ic | not initContainer[i].readinessProbe; ic := initContainer[i].name }
  check := check1 | check2
  count(check) > 0
  page := "https://learningcicd.github.io/14-disallow-pods-without-probes.html"
  msg := sprintf("Pod '%s' could not be created because its container(s) '[%s]' have no readinessProbe configuration. For more information, please visit %s.", [name, concat(", ", check), page])
}

match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
  input.request.kind.kind == "Pod"
  name := input.request.object.metadata.name
  container := input.request.object.spec.containers
  initContainer := input.request.object.spec.initContainers
  check1 := { c | not container[i].livenessProbe; c := container[i].name }
  check2 := { ic | not initContainer[i].livenessProbe; ic := initContainer[i].name }
  check := check1 | check2
  count(check) > 0
  page := "https://learningcicd.github.io/14-disallow-pods-without-probes.html"
  msg := sprintf("Pod '%s' could not be created because its container(s) '[%s]' have no livenessProbe configuration. For more information, please visit %s.", [name, concat(", ", check), page])
}