## Disallow hostPath

HostPath volumes let Pods use host directories and volumes in containers. Using host resources can be used to access shared data or escalate privileges and should not be allowed. This policy ensures no hostPath volumes (`spec.volumes[*].hostPath`) are in use.

**Rego Policy:**

```rego
match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
  input.request.kind.kind == "Pod"
  input.request.object.spec.volumes[_].hostPath
  page := "https://learningcicd.github.io/3-disallow-hostpath.html"
  msg := sprintf("HostPath volumes are forbidden. The field 'spec.volumes[*].hostPath' must be unset. For more information, please visit %s.", [page])
}
```

**Unit Tests:**

Run the following command to perform unit tests on this rego policy:

```bash
opa test -zv policies/3-disallow-hostpath.rego unit-tests/3-disallow-hostpath_test.rego
```

Output:

```text
unit-tests/3-disallow-hostpath_test.rego:
data.kubernetes.policies.test_allowed_config: PASS (997µs)
data.kubernetes.policies.test_disallowed_config: PASS (995.9µs)
--------------------------------------------------------------------------------
PASS: 2/2
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
  volumes:
    - name: host
      hostPath:
        path: /usr/share/tmp
  containers:
  - name: nginx
    image: nginx
    ports:
    - containerPort: 80
    volumeMounts:
      - name: host
        mountPath: /usr/share/nginx
```

**Alert generated if policy is violated:**

![3](./images/3.png)

**Remediation:**

Make sure that a POD does not use hostPath volumes (`spec.volumes[*].hostPath`). Instead of hostPath volume, it is advised to use persistentVolumeClaim, configMap or any other volume type.

An example POD yaml file which will violate the policy is given below along with remediation.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: demo3
spec:
  volumes:
    - name: host
      hostPath: # <- Volume Type must not be hostPath
        path: /usr/share/tmp
  containers:
  - name: nginx
    image: nginx
    volumeMounts:
      - name: host
        mountPath: /usr/share/nginx
```

---