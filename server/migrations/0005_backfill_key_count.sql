UPDATE secret_versions
SET key_count = json_array_length(changed_keys)
WHERE changed_keys IS NOT NULL AND key_count = 0;
