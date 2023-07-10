## Restrict Seccomp

The seccomp profile must not be explicitly set to `Unconfined`. This policy, requiring Kubernetes v1.19 or later, ensures that seccomp is unset or set to `RuntimeDefault` or `Localhost`. That is, the policy enforces that the following fields must either be unset or set to `RuntimeDefault` or `Localhost`:
- `spec.securityContext.seccompProfile.type`
- `spec.containers[*].securityContext.seccompProfile.type`
- `spec.initContainers[*].securityContext.seccompProfile.type`
- `spec.ephemeralContainers[*].securityContext.seccompProfile.type`

**Rego Policy:**

```rego
match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
  input.request.kind.kind == "Pod"
  allowed := {"", "RuntimeDefault", "Localhost"}
  not allowed[input.request.object.spec.securityContext.seccompProfile.type]
  page := "https://learningcicd.github.io/10-restrict-seccomp.html"
  msg := sprintf("Use of custom Seccomp profiles is disallowed. The field 'spec.securityContext.seccompProfile.type' must either be unset or set to 'RuntimeDefault' or 'Localhost'. For more information, please visit %s.", [page])
}

match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
  input.request.kind.kind == "Pod"
  allowed := {"", "RuntimeDefault", "Localhost"}
  check1 := { c | p := input.request.object.spec.containers[i].securityContext.seccompProfile.type; not allowed[p]; c := input.request.object.spec.containers[i].name }
  check2 := { c | p := input.request.object.spec.initContainers[i].securityContext.seccompProfile.type; not allowed[p]; c := input.request.object.spec.initContainers[i].name }
  check := check1 | check2
  count(check) > 0
  page := "https://learningcicd.github.io/10-restrict-seccomp.html"
  msg := sprintf("Use of custom Seccomp profiles is disallowed. The field 'securityContext.seccompProfile.type' for the containers '[%s]' must either be unset or set to 'RuntimeDefault' or 'Localhost'. For more information, please visit %s.", [concat(", ", check), page])
}
```

**Pod YAML for testing the Policy:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
  labels:
    app: nginx
spec:
  securityContext:
    seccompProfile:
      type: Unconfined
  containers:
  - name: nginx
    image: nginx
    ports:
    - containerPort: 80
    securityContext:
      seccompProfile:
        type: Localhost
        localhostProfile: Nginx
  initContainers:
  - name: redis
    image: redis
    ports:
    - containerPort: 6379
    securityContext:
      seccompProfile:
        type: RuntimeDefault
```

**Alert generated if policy is violated:**

![10](./images/10.png)

**Remediation:**

Make sure that a Pod or container does not set the seccomp profile to `Unconfined`. That is, the field `securityContext.seccompProfile.type` must be unset or set to `RuntimeDefault` or `Localhost` for a POD or container.

An example POD yaml file which will violate the policy is given below along with remediation.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: demo10
spec:
  securityContext:
    seccompProfile:
      type: Unconfined  # <- This field must either be removed or set to one of `RuntimeDefault` or `Localhost`.
  containers:
  - name: nginx
    image: nginx
    securityContext:
      seccompProfile:
        type: RuntimeDefault  # <- This field is correct.
```

---
