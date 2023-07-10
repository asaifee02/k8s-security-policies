## Missing Required Labels

This policy ensures that a Pod has all the following required labels set:
- `kubernetes.io/app`
- `env`

**Rego Policy:**

```rego
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
```

**Unit Tests:**

Run the following command to perform unit tests on this rego policy:

```bash
opa test -zv policies/18-missing-required-labels.rego unit-tests/18-missing-required-labels_test.rego
```

Output:

```text
unit-tests/18-missing-required-labels_test.rego:
data.kubernetes.policies.test_all_present: PASS (1.0281ms)
data.kubernetes.policies.test_env_missing: PASS (0s)
data.kubernetes.policies.test_app_missing: PASS (0s)
data.kubernetes.policies.test_all_missing: PASS (965.2µs)
--------------------------------------------------------------------------------
PASS: 4/4
```

**Pod YAML for testing the Policy:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
  labels:
    name: nginx
    env: prod
spec:
  containers:
  - name: nginx
    image: nginx
```

**Alert generated if policy is violated:**

![18](./images/18.png)

**Remediation:**

Make sure that a Pod has all the required labels. That is, `metadata.labels` for a POD must contain all the required labels - `kubernetes.io/app` and `env`. An example POD yaml file which will violate the policy is given below along with remediation.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: demo18
  labels:
    # Pod 'demo18' is invalid as the required label 'kubernetes.io/app' is not present.
    name: nginx
    env: prod
spec:
  containers:
  - name: nginx
    image: nginx
```

---
