# Releasing

# Releases go to npm. Bump the version, then publish — `prepublishOnly` rebuilds `dist/` from the current sources,
# so what is published always matches what is committed.

# ```shell
# make version-patch  # or version-minor / version-major
# make publish-dry    # inspect exactly what would be published
# make publish        # publish to npm
# git push --follow-tags
# ```
# 
# `make release` runs the full `check` target and then publishes, for when you want the verification and the release in one step.
