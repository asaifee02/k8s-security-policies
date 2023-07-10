## Exec or Attach to a Pod

This policy detects an exec or attach event for a Pod.

**Rego Policy:**

```rego
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
```

**Pod YAML for testing the Policy:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
  labels:
    name: nginx
spec:
  containers:
  - name: nginx
    image: nginx
```

**Alert generated if policy is violated:**

![17](./images/17.png)

**Remediation:**

This policy detects an exec or attach event for a Pod. Make sure you do not use the following commands to avoid violating the policy:

```bash
# Command 1
kubectl exec <pod_name> -- <args>

# Command 2
kubectl attach <pod_name> -c <container_name> [ -it ]

# Command 3
kubectl run <pod_name> --image <image_name> -it [ -- <args> ]
```

---
