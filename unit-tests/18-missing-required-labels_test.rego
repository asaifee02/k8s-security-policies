package kubernetes.policies

test_all_present {
  result := match with input as input1
  count(result) == 0
}

test_env_missing {
  result := match with input as input2
  count(result) == 1
}

test_app_missing {
  result := match with input as input3
  count(result) == 1
}

test_all_missing {
  result := match with input as input4
  count(result) == 1
}

input1 := {
  "kind": "Admissioninput",
  "request": {
      "operation": "CREATE",
      "kind": {
        "kind": "Pod",
        "version": "v1"
      },
      "object": {
          "metadata": {
              "name": "myapp",
              "labels": {
                "kubernetes.io/app": "nginx",
                "env": "prod"
              }
          },
          "spec": {
              "containers": [
                  {
                      "image": "nginx",
                      "name": "nginx",
                      "ports": [
                        {
                          "containerPort": 80
                        }
                      ]
                  }
              ]
          }
      }
  }
}

input2 := {
  "kind": "Admissioninput",
  "request": {
      "operation": "CREATE",
      "kind": {
        "kind": "Pod",
        "version": "v1"
      },
      "object": {
          "metadata": {
              "name": "myapp",
              "labels": {
                "kubernetes.io/app": "nginx"
              }
          },
          "spec": {
              "containers": [
                  {
                      "image": "nginx",
                      "name": "nginx",
                      "ports": [
                        {
                          "containerPort": 80
                        }
                      ]
                  }
              ]
          }
      }
  }
}

input3 := {
  "kind": "Admissioninput",
  "request": {
      "operation": "CREATE",
      "kind": {
        "kind": "Pod",
        "version": "v1"
      },
      "object": {
          "metadata": {
              "name": "myapp",
              "labels": {
                "env": "prod"
              }
          },
          "spec": {
              "containers": [
                  {
                      "image": "nginx",
                      "name": "nginx",
                      "ports": [
                        {
                          "containerPort": 80
                        }
                      ]
                  }
              ]
          }
      }
  }
}

input4 := {
  "kind": "Admissioninput",
  "request": {
      "operation": "CREATE",
      "kind": {
        "kind": "Pod",
        "version": "v1"
      },
      "object": {
          "metadata": {
              "name": "myapp",
              "labels": {
                "test": "fail"
              }
          },
          "spec": {
              "containers": [
                  {
                      "image": "nginx",
                      "name": "nginx",
                      "ports": [
                        {
                          "containerPort": 80
                        }
                      ]
                  }
              ]
          }
      }
  }
}
