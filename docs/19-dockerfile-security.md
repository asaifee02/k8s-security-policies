# Dockerfile Security

This policy prevents the following misconfigurations which lead to vulnerabilities:

- [Suspicious Environment Variables](#suspicious-environment-variables)
- [Latest Tag for Base Image](#latest-tag-for-base-image)
- [Distribution Upgrade Commands](#distribution-upgrade-commands)
- [Using ADD instead of COPY instruction](#using-add-instead-of-copy-instruction)
- [Using Sudo](#using-sudo)
- [Unallowed Docker Images](#unallowed-docker-images)
- [Unallowed Commands](#unallowed-commands)
- [Missing Metadata Labels](#missing-metadata-labels)

---

## Suspicious Environment Variables

This rule detects any suspicious environment variables set in the Dockerfile which might pose a danger to the environment, like a security breach.

The rule detects the following suspicious environment variables:

- `passwd`
- `password`
- `secret`
- `key`
- `access`
- `api_key`
- `apikey`
- `token`

---

#### Rego Policy:

```rego
package main
import future.keywords.in

suspicious_env_keys = [
    "passwd",
    "password",
    "secret",
    "key",
    "access",
    "api_key",
    "apikey",
    "token",
]

deny[msg] {    
    dockerenvs := [val | input[i].Cmd == "env"; val := input[i].Value]
    dockerenv := dockerenvs[_]
    envvar := dockerenv[_]
    lower(envvar) == suspicious_env_keys[_]
    msg = sprintf("Potential secret in ENV found: %s", [envvar])
}

deny[msg] {
    dockerenvs := [val | input[i].Cmd == "env"; val := input[i].Value]
    dockerenv := dockerenvs[_]
    envvar := dockerenv[_]
    startswith(lower(envvar), suspicious_env_keys[_])
    msg = sprintf("Potential secret in ENV found: %s", [envvar])
}

deny[msg] {
    dockerenvs := [val | input[i].Cmd == "env"; val := input[i].Value]
    dockerenv := dockerenvs[_]
    envvar := dockerenv[_]
    endswith(lower(envvar), suspicious_env_keys[_])
    msg = sprintf("Potential secret in ENV found: %s", [envvar])
}

deny[msg] {
    dockerenvs := [val | input[i].Cmd == "env"; val := input[i].Value]
    dockerenv := dockerenvs[_]
    envvar := dockerenv[_]
    parts := regex.split("[ :=_-]", envvar)
    part := parts[_]
    lower(part) == suspicious_env_keys[_]
    msg = sprintf("Potential secret in ENV found: %s", [envvar])
}
```

---

#### Dockerfile for testing the Policy:

```dockerfile
FROM alpine:3
RUN apk update && apk add ca-certificates python3 && rm -rf /var/cache/apk/*
WORKDIR /usr/src/app
USER app
# The below environment variable is insecure and thus will violate the policy
ENV api_key=my_s3cr3t_k3y
ENTRYPOINT [ "python" ]
CMD [ "app.py" ]
```

---

#### Alert generated if policy is violated:

```text
$ conftest test Dockerfile -p security.rego --fail-on-warn
FAIL - Dockerfile - main - Potential secret in ENV found: api_key

1 tests, 0 passed, 0 warnings, 1 failure, 0 exceptions
```

---

## Latest Tag for Base Image

This rule ensures that the **base image** used in the Dockerfile's `FROM` instruction does not have `latest` tag.

---

#### Rego Policy:

```rego
package main
import future.keywords.in

image_tag_list = [
    "latest",
    "LATEST",
]

deny[msg] {
    input[i].Cmd == "from"
    val := split(input[i].Value[0], ":")
    count(val) == 1
    msg = sprintf("Do not use latest tag with image: %s", [val])
}

deny[msg] {
    input[i].Cmd == "from"
    val := split(input[i].Value[0], ":")
    contains(val[1], image_tag_list[_])
    msg = sprintf("Do not use latest tag with image: %s", [input[i].Value])
}
```

---

#### Dockerfile for testing the Policy:

```dockerfile
FROM alpine:latest
RUN apk update && apk add ca-certificates python3 && rm -rf /var/cache/apk/*
WORKDIR /usr/src/app
USER app
ENTRYPOINT [ "python" ]
CMD [ "app.py" ]
```

---

#### Alert generated if policy is violated:

```text
$ conftest test Dockerfile -p security.rego --fail-on-warn
FAIL - Dockerfile - main - Do not use latest tag with image: ["alpine:latest"]

1 tests, 0 passed, 0 warnings, 1 failure, 0 exceptions
```

---

## Distribution Upgrade Commands

This rule detects the usage of distribution `upgrade` commands. Following are the commands detected by the rule:

- `apk upgrade`
- `apt-get upgrade`
- `apt upgrade`
- `dist-upgrade`
- `yum upgrade`

---

#### Rego Policy:

```rego
package main
import future.keywords.in

pkg_update_commands = [
    "apk upgrade",
    "apt-get upgrade",
    "apt upgrade",
    "dist-upgrade",
    "yum upgrade"
]

deny[msg] {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    contains(val, pkg_update_commands[_])
    msg = sprintf("Do not use upgrade commands: %s", [val])
}
```

---

#### Dockerfile for testing the Policy:

```dockerfile
FROM alpine:3
# Below is a distribution upgrade command which violates the policy
RUN apk upgrade
RUN apk add ca-certificates python3 && rm -rf /var/cache/apk/*
WORKDIR /usr/src/app
USER app
ENTRYPOINT [ "python" ]
CMD [ "app.py" ]
```

---

#### Alert generated if policy is violated:

```text
$ conftest test Dockerfile -p security.rego --fail-on-warn
FAIL - Dockerfile - main - Do not use upgrade commands: apk upgrade

1 tests, 0 passed, 0 warnings, 1 failure, 0 exceptions
```

---

## Using ADD instead of COPY instruction

The `ADD` instruction has been **deprecated** in favour of the `COPY` instruction due to its security vulnerabilities. This rule detects if an `ADD` instruction is used in a Dockerfile.

---

#### Rego Policy:

```rego
package main
import future.keywords.in

deny[msg] {
    input[i].Cmd == "add"
    val := concat(" ", input[i].Value)
    msg = sprintf("Use COPY instead of ADD: %s", [val])
}
```

---

#### Dockerfile for testing the Policy:

```dockerfile
FROM alpine:3
RUN apk update && apk add ca-certificates python3 && rm -rf /var/cache/apk/*
WORKDIR /usr/src/app
# Using ADD instruction violates the policy
ADD app.py .
USER app
ENTRYPOINT [ "python" ]
CMD [ "app.py" ]
```

---

#### Alert generated if policy is violated:

```text
$ conftest test Dockerfile -p security.rego --fail-on-warn
FAIL - Dockerfile - main - Use COPY instruction instead of ADD: app.py .

1 tests, 0 passed, 0 warnings, 1 failure, 0 exceptions
```

---

## Using Sudo

`sudo` command invites many security vulnerabilities into the built Docker Image. This rule detects `sudo` usage in the Dockerfile.

---

#### Rego Policy:

```rego
package main
import future.keywords.in

deny[msg] {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    contains(lower(val), "sudo")
    msg = sprintf("Avoid using 'sudo' command: %s", [val])
}
```

---

#### Dockerfile for testing the Policy:

```dockerfile
FROM alpine:3
RUN apk update && apk add ca-certificates python3 && rm -rf /var/cache/apk/*
WORKDIR /usr/src/app
# The below RUN instruction uses sudo command which violtes the policy
RUN sudo passwd
USER app
ENTRYPOINT [ "python" ]
CMD [ "app.py" ]
```

---

#### Alert generated if policy is violated:

```text
$ conftest test Dockerfile -p security.rego --fail-on-warn
FAIL - Dockerfile - main - Avoid using 'sudo' command: sudo passwd

1 tests, 0 passed, 0 warnings, 1 failure, 0 exceptions
```

---

## Unallowed Docker Images

This rule ensures that the following images are not used as base image in Dockerfile:

- `python`
- `ruby`
- `node`
- `openjdk`

---

#### Rego Policy:

```rego
package main
import future.keywords.in

denylist = ["python", "node", "ruby", "openjdk"]

deny[msg] {
	input[i].Cmd == "from"
	val := input[i].Value
	contains(val[0], denylist[_])
	msg := sprintf("Unallowed image found: '%s'", [val[0]])
}
```

---

#### Dockerfile for testing the Policy:

```dockerfile
# This image is not allowed, hence it violates the policy
FROM python:3
WORKDIR /usr/src/app
USER app
ENTRYPOINT [ "python" ]
CMD [ "app.py" ]
```

---

#### Alert generated if policy is violated:

```text
$ conftest test Dockerfile -p security.rego --fail-on-warn
FAIL - Dockerfile - main - Unallowed image found: 'python:3'

1 tests, 0 passed, 0 warnings, 1 failure, 0 exceptions
```

---

## Unallowed Commands

The following shell commands are not allowed to be used in the `RUN` instruction of a Dockerfile by the policy because they can pose security risk in the resulting Docker Image:

- `apk`
- `apt`
- `pip`
- `curl`
- `wget`

---

#### Rego Policy:

```rego
package main
import future.keywords.in

unallowed_commands = [
	"apk",
	"apt",
	"pip",
	"curl",
	"wget",
]

deny[msg] {
	input[i].Cmd == "run"
	val := input[i].Value
	contains(val[j], unallowed_commands[_])
	msg = sprintf("Unallowed command found: '%s'", [val[j]])
}
```

---

#### Dockerfile for testing the Policy:

```dockerfile
FROM alpine:3
# Below RUN instruction uses `curl` command which is not allowed by the policy
RUN curl http://google.com
WORKDIR /usr/src/app
USER app
ENTRYPOINT [ "python" ]
CMD [ "app.py" ]
```

---

#### Alert generated if policy is violated:

```text
$ conftest test Dockerfile -p security.rego --fail-on-warn
FAIL - Dockerfile - main - Unallowed command found: 'curl http://google.com'

1 tests, 0 passed, 0 warnings, 1 failure, 0 exceptions
```

---

## Missing Metadata Labels

This rule ensures that the following metadata `labels` are present in the Dockerfile:

- `name`
- `version`
- `source`
- `summary`
- `team`

---

#### Rego Policy:

```rego
package main
import future.keywords.in

metadata = [
    "name",
    "version",
    "source",
    "summary",
    "team"
]

deny[msg] {
    input[i].Cmd == "label"
    val := input[i].Value
    count(val) > 2
    labels := [ l | tmp := val[j]; z := j % 2; z == 0; l := tmp ]
    not metadata[k] in labels
    msg := sprintf("Metadata LABEL '%s' not found.", [metadata[k]])
}

deny[msg] {
    labels := [ l | input[i].Cmd == "label"; val := input[i].Value; count(val) == 2; l := val[0]]
    count(labels) > 0
    not metadata[k] in labels
    msg := sprintf("Metadata LABEL '%s' not found.", [metadata[k]])
}
```

---

#### Dockerfile for testing the Policy:

```dockerfile
FROM alpine:3
# `team` label is missing, which violates the policy
LABEL name="default" \
      version="1.0" \
      source="https://github.com/one-thd/cns-base-images" \
      summary="Alpine Image"
RUN apk update && apk add ca-certificates python3 && rm -rf /var/cache/apk/*
WORKDIR /usr/src/app
USER app
ENTRYPOINT [ "python" ]
CMD [ "app.py" ]
```

---

#### Alert generated if policy is violated:

```text
$ conftest test Dockerfile -p security.rego --fail-on-warn
FAIL - Dockerfile - main - Metadata LABEL 'team' not found.

1 tests, 0 passed, 0 warnings, 1 failure, 0 exceptions
```

---
