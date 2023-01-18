author      = "Wolfi J. Inkinson"
author_role = "Senior VEXing Engineer"
timestamp   = "2023-01-09T21:23:03.579712389-06:00"
version     = "1"

statement "CVE-2021-0001" {
  products = [
    "pkg:oci/git@sha256:23a264e6e429852221a963e9f17338ba3f5796dc7086e46439a6f4482cf6e0cb"
  ]
  subcomponents = [
    "pkg:apk/alpine/git@2.38.1-r0?arch=x86_64",
    "pkg:apk/alpine/git@2.38.1-r0?arch=ppc64le"
  ]
  status = "not_affected"
  justification = "inline_mitigations_already_exist"
  impact_statement = "Included git is mitigated against CVE-2023-12345 !"
}