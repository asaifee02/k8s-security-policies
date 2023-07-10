# METADATA
# scope: package
# title: Missing Required Labels
# description: This policy ensures that a Pod has all the required labels.
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
  pod := input.request.object.metadata.name
  pod_labels := { l | input.request.object.metadata.labels[l] }
  required_labels := { "kubernetes.io/app", "env" }
  missing := required_labels - pod_labels
  count(missing) > 0
  page := "https://learningcicd.github.io/18-missing-required-labels.html"
  msg := sprintf("Pod '%s' is missing the required labels '[%s]'. For more information, please visit %s.", [pod, concat(", ", missing), page])
}
