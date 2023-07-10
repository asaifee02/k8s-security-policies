# METADATA
# scope: package
# title: Restrict ImagePullPolicy
# description: This policy ensures that every container's imagePullPolicy is set to Always.
# related_resources:
# - ref: https://stackoverflow.com/questions/57215331/what-would-be-the-opa-policy-in-rego-for-the-following-examples
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
  check1 := { c | container[i].imagePullPolicy != "Always"; c := container[i].name }
  check2 := { c | initContainer[i].imagePullPolicy != "Always"; c := initContainer[i].name }
  check := check1 | check2
  count(check) > 0
  page := "https://learningcicd.github.io/15-restrict-imagepullpolicy.html"
  msg := sprintf("ImagePullPolicy must be set to 'Always'. Pod '%s' could not be created because imagePullPolicy for the containers '[%s]' is not set to 'Always'. For more information, please visit %s.", [name, concat(", ", check), page])
}
