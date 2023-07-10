package kubernetes.policies

test_host_network {
  result := match with input as input1
  count(result) == 1
}

test_host_ipc {
  result := match with input as input2
  count(result) == 1
}

test_host_pid {
  result := match with input as input3
  count(result) == 1
}

test_allowed_config {
  result := match with input as input4
  count(result) == 0
}

test_host_network_ipc {
  result := match with input as input5
  count(result) == 2
}

test_host_network_pid {
  result := match with input as input6
  count(result) == 2
}

test_host_ipc_pid {
  result := match with input as input7
  count(result) == 2
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
              "hostNetwork": true,
              "hostIPC": false,
              "hostPID": false,
              "containers": [
                  {
                      "image": "hooli.com/nginx",
                      "name": "nginx-frontend"
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
              "hostNetwork": false,
              "hostIPC": true,
              "hostPID": false,
              "containers": [
                  {
                      "image": "hooli.com/nginx",
                      "name": "nginx-frontend"
                  }
              ]
          }
      }
  }
}

input3 := {
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
              "hostNetwork": false,
              "hostIPC": false,
              "hostPID": true,
              "containers": [
                  {
                      "image": "hooli.com/nginx",
                      "name": "nginx-frontend"
                  }
              ]
          }
      }
  }
}

input4 := {
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
              "containers": [
                  {
                      "image": "hooli.com/nginx",
                      "name": "nginx-frontend"
                  }
              ]
          }
      }
  }
}

input5 := {
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
              "hostNetwork": true,
              "hostIPC": true,
              "hostPID": false,
              "containers": [
                  {
                      "image": "hooli.com/nginx",
                      "name": "nginx-frontend"
                  }
              ]
          }
      }
  }
}

input6 := {
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
              "hostNetwork": true,
              "hostIPC": false,
              "hostPID": true,
              "containers": [
                  {
                      "image": "hooli.com/nginx",
                      "name": "nginx-frontend"
                  }
              ]
          }
      }
  }
}

input7 := {
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
              "hostNetwork": false,
              "hostIPC": true,
              "hostPID": true,
              "containers": [
                  {
                      "image": "hooli.com/nginx",
                      "name": "nginx-frontend"
                  }
              ]
          }
      }
  }
}
