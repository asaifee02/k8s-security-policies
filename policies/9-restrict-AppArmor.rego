# METADATA
# scope: package
# title: Restrict AppArmor
# description: This policy ensures Pods do not specify any other AppArmor profiles than `runtime/default` or `localhost/*`.
# related_resources:
# - ref: https://kyverno.io/policies/pod-security/baseline/restrict-apparmor-profiles/restrict-apparmor-profiles/
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
  profiles := { x | annot := input.request.object.metadata.annotations[i]; startswith(i, "container.apparmor.security.beta.kubernetes.io/"); annot != "runtime/default"; not startswith(annot, "localhost/"); x := annot }
  count(profiles) > 0
  page := "https://learningcicd.github.io/9-restrict-apparmor.html"
  msg := sprintf("Specifying other AppArmor profiles is disallowed. The annotation 'container.apparmor.security.beta.kubernetes.io' if defined must not be set to anything other than 'runtime/default' or 'localhost/*'. For more information, please visit %s.", [page])
}
