## Disallow hostProcess

Windows pods offer the ability to run HostProcess containers which enables privileged access to the Windows node. Privileged access to the host is disallowed in the baseline policy. HostProcess pods are an alpha feature as of Kubernetes v1.22. This policy ensures that the following fields, if present, are set to `false`:
- `spec.securityContext.windowsOptions.hostProcess`
- `spec.containers[*].securityContext.windowsOptions.hostProcess`
- `spec.initContainers[*].securityContext.windowsOptions.hostProcess`
- `spec.ephemeralContainers[*].securityContext.windowsOptions.hostProcess`

**Rego Policy:**

```rego
match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
  input.request.kind.kind == "Pod"
  host1 := { c | h := input.request.object.spec.containers[i].securityContext.windowsOptions.hostProcess; h; c := input.request.object.spec.containers[i].name }
  host2 := { c | h := input.request.object.spec.initContainers[i].securityContext.windowsOptions.hostProcess; h; c := input.request.object.spec.initContainers[i].name }
  host := host1 | host2
  count(host) > 0
  page := "https://learningcicd.github.io/5-disallow-hostprocess.html"
  msg := sprintf("HostProcess containers are disallowed. The field 'securityContext.windowsOptions.hostProcess' for the containers '[%s]' must either be unset or set to 'false'. For more information, please visit %s.", [concat(", ", host), page])
}

match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
  input.request.kind.kind == "Pod"
  input.request.object.spec.securityContext.windowsOptions.hostProcess
  page := "https://learningcicd.github.io/5-disallow-hostprocess.html"
  msg := sprintf("HostProcess containers are disallowed. The field 'spec.securityContext.windowsOptions.hostProcess' must either be unset or set to 'false'. For more information, please visit %s.", [page])
}```

**Pod YAML for testing the Policy:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
  labels:
    app: nginx
spec:
  containers:
  - name: nginx
    image: nginx
    ports:
    - containerPort: 80
    securityContext:
      windowsOptions:
        hostProcess: true
```

**Alert generated if policy is violated:**

No alerts available as of now.

**Remediation:**

Make sure that a POD or a container do not run as HostProcess as it allows privileged access to the underlying host. That is, the field `securityContext.windowsOptions.hostProcess` must not be set under a POD or container and if it is set, then it's value must be `false`.

An example POD yaml file which will violate the policy is given below along with remediation.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: demo5
spec:
  securityContext:
    windowsOptions:
      hostProcess: true # <- This field must be removed or set to 'false'
  containers:
  - name: nginx
    image: nginx
    securityContext:
      windowsOptions:
        hostProcess: true # <- This field must be removed or set to 'false'
```

---
