## Disallow Privileged Containers

Privileged mode disables most security mechanisms and must not be allowed. This policy ensures Pods do not call for privileged mode. This policy enforces that the followings fields must be either unset or set to `false`:
- `spec.containers[*].securityContext.privileged`
- `spec.initContainers[*].securityContext.privileged`

**Rego Policy:**

```rego
match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
  input.request.kind.kind == "Pod"
  check1 := { c | p := input.request.object.spec.containers[i].securityContext.privileged; p; c := input.request.object.spec.containers[i].name }
  check2 := { c | p := input.request.object.spec.initContainers[i].securityContext.privileged; p; c := input.request.object.spec.initContainers[i].name }
  check := check1 | check2
  count(check) > 0
  page := "https://learningcicd.github.io/6-disallow-privileged-containers.html"
  msg := sprintf("Privileged mode is disallowed. The field 'securityContext.privileged' for the containers '[%s]' must either be unset or set to 'false'. For more information, please visit %s.", [concat(", ", check), page])
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
  containers:
  - name: nginx
    image: nginx
    ports:
    - containerPort: 80
    securityContext:
      privileged: true
```

**Alert generated if policy is violated:**

![6](./images/6.png)

**Remediation:**

Make sure that a POD does not call for privileged mode. That is, every container of the POD must have `securityContext.privileged` field either unset or set to `false`.

An example POD yaml file which will violate the policy is given below along with remediation.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: demo6
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      privileged: true  # <- This field must be removed or set to 'false'
```

---
