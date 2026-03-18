# rage-helper awesome bash script to make rage app WAY easier to use 




This is an awesome helper for the rage app https://github.com/str4d/rage Instead of using complicated commands, you just make sure rage is in same dir as the .sh file. Here is an example - I rename encrypt_decrypt.sh to rge.sh  THEN the ONLY command you need is ./rge.sh example.txt   where "example.txt" is any file you want to encrypt. That is it, ONE COMMAND! IF the file is not encrypted you will be prompted for a password to encrypt it. IF the file is already encrypted, you will be promped for the password to decrypt the file! As such, the .sh file makes using Rage way easier and user friendly. You do NOT have to specify an output file because this handles everything for you- it encrypts to another file, then deletes the original and renames the encrypted file to the original! So with just one SIMPLE command, the file name, you encrypt or decrypt the file right in place. this makes password mode way easier. 

on cosmic desktop, the sh file opens a dialog box window for you to enter password, that is really neat. 


This Bash script provides a simple way to toggle encryption and decryption of files "in place" using the `rage` tool (a Rust implementation of the Age encryption format). It overwrites the original file, making it appear as if the encryption/decryption happens directly on the file without creating copies.

The script automatically detects if a file is encrypted (by checking for the Age header "age-encryption.org/v1\n") and decrypts it if so, or encrypts it otherwise. It uses a temporary file during the process to ensure safety.

## Requirements

- **rage**: The `rage` binary must be in the same directory as the script (e.g., `./rage`). You can download and compile it from the official GitHub repository: [str4d/rage](https://github.com/str4d/rage).
- **Bash**: Available on most Linux/Unix systems (tested on Pop!_OS).
- **Permissions**: The script needs read/write access to the target file and execute permissions on itself.

## Setup

1. Save the script as `encrypt_decrypt.sh` in your working directory.
2. Make it executable:
   ```
   chmod +x encrypt_decrypt.sh
   ```
3. Ensure `rage` is in the same directory and executable:
   ```
   chmod +x rage
   ```

## Usage

Run the script with a single filename as an argument:

```
./encrypt_decrypt.sh <filename>
```

- **Encryption**: If the file is not encrypted, you'll be prompted for a passphrase (via `rage`). Leave blank to autogenerate one (note it down manually for later decryption).
- **Decryption**: If the file is encrypted (has the Age header), you'll be prompted for the passphrase to decrypt it.
- Output: The script will echo "File encrypted in place." or "File decrypted in place." on success.

Example:
```
./encrypt_decrypt.sh example.txt
```

### Notes
- **Passphrase Prompt**: On desktop Linux (e.g., Pop!_OS), the prompt may appear in a graphical dialog (using tools like `pinentry`).
- **Double Encryption**: If you encrypt an already-encrypted file, it adds another layer. The script warns about this but proceeds. To fully decrypt, run the script multiple times (once per layer).
- **Safety**: Always back up important files before use, as this overwrites the original. If an operation fails, the temporary file is deleted, and the original remains unchanged.
- **Header Detection**: Relies on the first 22 bytes matching "age-encryption.org/v1\n". This may not catch all edge cases.
- **Limitations**: Does not handle directories, symlinks, or very large files efficiently. For production use, consider error handling enhancements.

## Troubleshooting

- **File not found**: Ensure the file exists in the current directory.
- **Permission issues**: Run with sufficient privileges or check file ownership.
- **rage not found**: Verify `./rage` exists and is executable.
- **Debugging**: Add `set -x` at the top of the script for verbose output.

If you encounter issues, check the `rage` documentation or provide more details for debugging.

## License

This script is provided as-is under the MIT License. Feel free to modify and distribute.
