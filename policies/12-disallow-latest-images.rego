# METADATA
# scope: package
# title: Disallow images tagged as 'latest'
# description: This policy ensures that no container uses an image which is tagged as latest or is untagged.
# related_resources:
# - ref: https://www.magalix.com/blog/enforce-that-all-kubernetes-container-images-must-have-a-label-that-is-not-latest-using-opa
# authors:
# - name: Adnan Saifee
#   email: asaifee02@gmail.com
# schemas: 
#   - input: schema["input"]
#   - input.request.object: schema.kubernetes["pod"]
package kubernetes.policies

match[{"msg": msg}] {
  operations := { "CREATE", "UPDATE" }
  operations[input.request.operation]
  input.request.kind.kind == "Pod"
  container := input.request.object.spec.containers
  initContainer := input.request.object.spec.initContainers
  c_images := { c | img := container[i].image; ensure(img); c := container[i].name }
  ic_images := { ic | img := initContainer[_].image; ensure(img); ic := initContainer[i].name }
  images := c_images | ic_images
  count(images) > 0
  page := "https://learningcicd.github.io/12-disallow-images-tagged-as-latest.html"
  msg := sprintf("Container(s) '[%s]' could not be created because either their image is tagged as 'latest' or doesn't have a tag. For more information, please visit %s.",[concat(", ", images), page])
}

ensure(img) {
  contains(img, ":latest")
}

ensure(img) {
  not contains(img, ":")
}
