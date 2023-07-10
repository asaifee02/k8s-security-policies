# METADATA
# scope: package
# title: Exec or Attach to a Pod
# description: This policy detects an exec or attach event for a Pod.
# authors:
# - name: Adnan Saifee
#   email: asaifee02@gmail.com
# schemas: 
#   - input: schema["input"]
#   - input.request.object: schema.kubernetes["exec-attach"]
package kubernetes.policies

match[{"msg": msg}]{
  input.request.operation == "CONNECT"
  input.request.resource.resource == "pods"
  pod := input.request.name
  container := input.request.object.container
  exec_or_attach(input.request.subResource)
  page := "https://learningcicd.github.io/17-exec-or-attach-to-a-pod.html"
  msg := sprintf("Exec or attach to the container '%s' of pod '%s' detected. For more information, please visit %s.", [container, pod, page])
}

exec_or_attach(v) {
  v == "exec"
}

exec_or_attach(v) {
  v == "attach"
}
