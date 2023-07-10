package kubernetes.policies

test_allowed_caps {
  result := match with input as input1
  count(result) == 0
}

test_container_disallowed_caps {
  result := match with input as input3
  count(result) == 1
}

test_initcontainer_disallowed_caps {
  result := match with input as input4
  count(result) == 1
}

test_disallowed_caps {
  result := match with input as input2
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
            "containers": [
                {
                    "image": "hooli.com/nginx",
                    "name": "nginx-frontend",
                    "securityContext": {
                        "capabilities": {
                            "add": [
                                "MKNOD",
                                "KILL"
                            ]
                        }
                    }
                }
            ],
            "initContainers": [
                {
                    "image": "hooli.com/nginx",
                    "name": "nginx-frontend",
                    "securityContext": {
                        "capabilities": {
                            "add": [
                                "FOWNER",
                                "FSETID"
                            ]
                        }
                    }
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
            "containers": [
                {
                    "image": "hooli.com/nginx",
                    "name": "nginx-frontend",
                    "securityContext": {
                        "capabilities": {
                            "add": [
                                "MKNOD",
                                "ROOT",
                                "HEELOO"
                            ]
                        }
                    }
                }
            ],
            "initContainers": [
                {
                    "image": "hooli.com/nginx",
                    "name": "nginx-frontend",
                    "securityContext": {
                        "capabilities": {
                            "add": [
                                "TEST"
                            ]
                        }
                    }
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
            "containers": [
                {
                    "image": "hooli.com/nginx",
                    "name": "nginx-frontend",
                    "securityContext": {
                        "capabilities": {
                            "add": [
                                "ROOT",
                                "HEELOO"
                            ]
                        }
                    }
                }
            ],
            "initContainers": [
                {
                    "image": "hooli.com/nginx",
                    "name": "nginx-frontend",
                    "securityContext": {
                        "capabilities": {
                            "add": [
                                "MKNOD"
                            ]
                        }
                    }
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
                    "name": "nginx-frontend",
                    "securityContext": {
                        "capabilities": {
                            "add": [
                                "AUDIT_WRITE",
                                "CHOWN"
                            ]
                        }
                    }
                }
            ],
            "initContainers": [
                {
                    "image": "hooli.com/nginx",
                    "name": "nginx-frontend",
                    "securityContext": {
                        "capabilities": {
                            "add": [
                                "DAC_OVERRIDE",
                                "ROOT"
                            ]
                        }
                    }
                }
            ]
            }
        }
    }
}
