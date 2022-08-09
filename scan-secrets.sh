detect-secrets scan \
  --filter ./icure-pre-commit/icure_detect_secrets/filters/is_icure_safe_data.py::is_icure_safe_data \
  --filter ./icure-pre-commit/icure_detect_secrets/filters/is_key_format.py::is_key_format \
  --plugin ./icure-pre-commit/icure_detect_secrets/plugins/EncodedFileDetector.py \
  --plugin ./icure-pre-commit/icure_detect_secrets/plugins/KeyFileDetector.py \
  "$@" > .secrets.baseline
echo "Scan done, remember to update the .secrets.baseline plugins with relative paths to the plugin scripts."
