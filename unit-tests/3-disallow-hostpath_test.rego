package kubernetes.policies

test_allowed_config {
  result := match with input as input1
  count(result) == 0
}

test_disallowed_config {
  result := match with input as input2
  count(result) == 1
}

input1 := {
  "kind": "AdmissionReview",
  "request": {
      "operation": "CREATE",
      "kind": {
        "kind": "Pod",
        "version": "v1"
      },
      "object": {
          "metadata": {
              "name": "myapp"
          },
          "spec": {
              "volumes": [
                   {
                      "name": "host",
                      "emptyDir": {}
                  }
              ],
              "containers": [
              {
                  "image": "hooli.com/nginx",
                  "name": "nginx-frontend",
                  "volumeMounts": [
                      {
                          "name": "host",
                          "mountPath": "/usr/share/nginx"
                      }
                  ]
              }
              ]
          }
      }
  }
}

input2 := {
  "kind": "AdmissionReview",
  "request": {
      "operation": "CREATE",
      "kind": {
        "kind": "Pod",
        "version": "v1"
      },
      "object": {
          "metadata": {
              "name": "myapp"
          },
          "spec": {
              "volumes": [
                   {
                      "name": "host",
                      "hostPath": {
                          "path": "/usr/share/tmp"
                      }
                  }
              ],
              "containers": [
              {
                  "image": "hooli.com/nginx",
                  "name": "nginx-frontend",
                  "volumeMounts": [
                      {
                          "name": "host",
                          "mountPath": "/usr/share/nginx"
                      }
                  ]
              }
              ]
          }
      }
  }
}
