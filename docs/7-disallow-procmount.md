## Disallow procMount

The default `/proc` masks are set up to reduce attack surface and should be required. This policy ensures nothing but the default procMount can be specified by enforcing that the following fields must either be **unset** or set to `Default`:
- `spec.containers[*].securityContext.procMount`
- `spec.initContainers[*].securityContext.procMount`
- `spec.ephemeralContainers[*].securityContext.procMount`

**NOTE:** In order for users to deviate from the `Default` procMount, [setting a feature gate](https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/#:~:text=for%20more%20details.-,ProcMountType,-%3A%20Enables%20control%20over "ProcMountType Feature Gate") at the API server is required.

**Rego Policy:**

```rego
match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
  input.request.kind.kind == "Pod"
  check1 := { c | p := input.request.object.spec.containers[i].securityContext.procMount; p != "Default"; c := input.request.object.spec.containers[i].name }
  check2 := { c | p := input.request.object.spec.initContainers[i].securityContext.procMount; p != "Default"; c := input.request.object.spec.initContainers[i].name }
  check := check1 | check2
  count(check) > 0
  page := "https://learningcicd.github.io/7-disallow-procmount.html"
  msg := sprintf("Changing the procMount from the default is not allowed. The field 'securityContext.procMount' for the containers '[%s]' must either be unset or set to 'Default'. For more information, please visit %s.", [concat(", ", check), page])
}
```

**Pod YAML for testing the Policy:**

```yaml
# Note that to deviate from the `Default` procMount requires setting a feature gate at the API server.
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
      procMount: "Unmasked"
```

**Alert generated if policy is violated:**

No alerts available as of now.

**Remediation:**

Make sure that every container in a POD specifies the `Default` procMount. That is, the field `securityContext.procMount` must be unset or set to `Default` for every container in a POD.

An example POD yaml file which will violate the policy is given below along with remediation.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: demo7
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      procMount: "Unmasked" # <- This field must be removed or set to 'Default'
```

---
