## Disallow Capabilities

This policy ensures that adding capabilities beyond those listed in the policy will be disallowed.

Allowed capabilities are:
- `AUDIT_WRITE`
- `CHOWN`
- `DAC_OVERRIDE`
- `FOWNER`
- `FSETID`
- `KILL`
- `MKNOD`
- `NET_BIND_SERVICE`
- `SETFCAP`
- `SETGID`
- `SETPCAP`
- `SETUID`
- `SYS_CHROOT`

**Rego Policy:**

```rego
match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
  input.request.kind.kind == "Pod"
  caps1 := { x | x := input.request.object.spec.containers[_].securityContext.capabilities.add[_] }
  caps2 := { x | x := input.request.object.spec.initContainers[_].securityContext.capabilities.add[_] }
  caps := caps1 | caps2
  allowed := {"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"}
  disallowed := caps - allowed
  count(disallowed) > 0
  page := "https://learningcicd.github.io/1-disallow-capabilities.html"
  msg := sprintf("Capabilities '%v' are not allowed. For more information, please visit %s.", [disallowed, page])
}
```

**Unit Tests:**

Run the following command to perform unit tests on this rego policy:

```bash
opa test -zv policies/1-disallow-capabilities.rego unit-tests/1-disallow-capabilities_test.rego
```

Output:

```text
unit-tests/1-disallow-capabilities_test.rego:
data.kubernetes.policies.test_allowed_caps: PASS (1.0006ms)
data.kubernetes.policies.test_container_disallowed_caps: PASS (0s)
data.kubernetes.policies.test_initcontainer_disallowed_caps: PASS (996.3µs)
data.kubernetes.policies.test_disallowed_caps: PASS (0s)
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
    app: nginx
spec:
  containers:
  - name: nginx
    image: nginx
    ports:
    - containerPort: 80
    securityContext:
      capabilities:
        add:
          - "CHOWN"
          - "NET_RAW"
```

**Alert generated if policy is violated:**

![1](./images/1.png)

**Remediation:**

Do not add capabilities other than the ones mentioned in the allowed capabilities list above. An example POD yaml file which will violate the policy is given below along with remediation.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: demo1
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      capabilities:
        add:
          - "NET_ADMIN" # <- Remove this capability as it is not mentioned in the allowed list
          - "AUDIT_WRITE" # This capability will be allowed as it is mentioned in the allowed list
```

---