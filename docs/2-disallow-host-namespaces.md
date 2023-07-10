## Disallow Host Namespaces

Host namespaces (Process ID namespace, Inter-Process Communication namespace, and network namespace) allow access to shared information and can be used to elevate privileges. Pods should not be allowed access to host namespaces. This policy ensures fields which make use of these host namespaces (`spec.hostNetwork`, `spec.hostIPC`, and `spec.hostPID`) are unset or set to `false`.

**Rego Policy:**

```rego
match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
	input.request.kind.kind == "Pod"
	input.request.object.spec.hostNetwork
  page := "https://learningcicd.github.io/2-disallow-host-namespaces.html"
  msg := sprintf("The field 'spec.hostNetwork' must be unset or set to 'false'. For more information, please visit %s.", [page])
}

match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
	input.request.kind.kind == "Pod"
  input.request.object.spec.hostIPC
  page := "https://learningcicd.github.io/2-disallow-host-namespaces.html"
  msg := sprintf("The field 'spec.hostIPC' must be unset or set to 'false'. For more information, please visit %s.", [page])
}

match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
	input.request.kind.kind == "Pod"
  input.request.object.spec.hostPID
  page := "https://learningcicd.github.io/2-disallow-host-namespaces.html"
  msg := sprintf("The field 'spec.hostPID' must be unset or set to 'false'. For more information, please visit %s.", [page])
}
```

**Unit Tests:**

Run the following command to perform unit tests on this rego policy:

```bash
opa test -zv policies/2-disallow-host-ns.rego unit-tests/2-disallow-host-ns_test.rego
```

Output:

```text
unit-tests/2-disallow-host-ns_test.rego:
data.kubernetes.policies.test_host_network: PASS (602.9µs)
data.kubernetes.policies.test_host_ipc: PASS (0s)
data.kubernetes.policies.test_host_pid: PASS (504µs)
data.kubernetes.policies.test_allowed_config: PASS (0s)
data.kubernetes.policies.test_host_network_ipc: PASS (0s)
data.kubernetes.policies.test_host_network_pid: PASS (0s)
data.kubernetes.policies.test_host_ipc_pid: PASS (512.9µs)
--------------------------------------------------------------------------------
PASS: 7/7
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
  hostNetwork: true
  containers:
  - name: nginx
    image: nginx
    ports:
    - containerPort: 8081
```

**Alert generated if policy is violated:**

![2](./images/2.png)

**Remediation:**

Make sure that `spec.hostNetwork`, `spec.hostIPC`, and `spec.hostPID` fields are unset or set to `false`. An example POD yaml file which will violate the policy is given below along with remediation.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: demo2
spec:
  containers:
  - name: nginx
    image: nginx
    # Ideally, the below three fields must not be set. But if set, it's value must be 'false'
    hostNetwork: true # <- This field should be set to false
    hostIPC: true # <- This field should be set to false
    hostPID: true # <- This field should be set to false
```

---