# METADATA
# scope: package
# title: Disallow pods without resources
# description: This policy ensures that every pod specifies resource requests and limits (cpu and memory) for all of its containers.
# related_resources:
# - ref: https://stackoverflow.com/questions/70651505/rego-opa-policy-to-check-if-resources-are-provided-for-deployment-in-kubernetes
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
  check1 := { c | missing_resources(container[i]); c := container[i].name }
  check2 := { ic | missing_resources(initContainer[i]); ic := initContainer[i].name }
  check := check1 | check2
  count(check) > 0
  page := "https://learningcicd.github.io/13-disallow-pods-without-resources.html"
  msg := sprintf("Pod '%s' could not be created because its container(s) '[%s]' are missing resource requests and limits. For more information, please visit %s.", [name, concat(", ", check), page])
}

missing_resources(container) {
  not container.resources.limits.cpu
}

missing_resources(container) {
  not container.resources.limits.memory
}

missing_resources(container) {
  not container.resources.requests.cpu
}

missing_resources(container) {
  not container.resources.requests.memory
}