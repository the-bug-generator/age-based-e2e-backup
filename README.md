# age-based e2e backup
A naive bash script to perform an incremental encrypted backup from one folder to another

Developped for my personal use of pCloud, but would work for any cloud storage provider that allows you to mount the cloud storage as a network drive.

```text
Usage: ./age-based-e2e-backup.sh [OPTIONS]

Options:
  -s, --sync
      Incremental E2E backup of SRC_PATH to DEST_PATH
  -r, --restore
      Restores encrypted files from SRC_PATH to DEST_PATH
  -c, --check
      Checks that files in backup are OK, by comparing sha2 hash of encrypted files from SRC_PATH with sha2 hash of cleartext files from DEST_PATH
  -i, --init
      Initializes a new age key pair for encryption/decryption.
      Store the keys securely, as backups will be useless if lost.
  -f, --from SRC_PATH
      Specifies the source directory for sync, restore or check.
  -t, --to DEST_PATH
      Specifies the destination directory for sync, restore or check.
  -k, --key KEY_PATH
      Specifies the path to the age key file.
  -T, --threads NUM
      Specifies the number of threads to use for processing (default: 3).
  -I, --include REGEX
      Specifies a regex pattern for files to include (see grep -E documentation).
  -X, --exclude REGEX
      Specifies a regex pattern for files to exclude (see grep -E documentation).

Examples:
  ./age-based-e2e-backup.sh -s -f /path/to/source -t /path/to/destination -k /path/to/keyfile -T 4
  ./age-based-e2e-backup.sh -r -f /path/to/source -t /path/to/destination -k /path/to/keyfile -T 4
  ./age-based-e2e-backup.sh -c -f /path/to/source -t /path/to/destination -k /path/to/keyfile -T 4
  ./age-based-e2e-backup.sh -i
```
