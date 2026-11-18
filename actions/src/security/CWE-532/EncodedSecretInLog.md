# Encoded secret written to workflow log

GitHub Actions masks the values of secrets when they appear in workflow logs. The runner masks the secret itself and a fixed set of its encodings, such as Base64 (at three alignments), JSON, URL and XML escapes. It does not recognize other transformations, for example `base32`, `xxd`, `od`, `hexdump` or `rev`, so a secret that is transformed this way and printed is written to the log in clear. Base64 output is also only masked when the encoded text of the whole value appears unbroken. The trailing newline that `echo` adds changes the end of the encoded text, and `base64` wraps long output into lines of 76 characters, so printing the Base64 encoding of a secret can still leave all or part of it readable. Anyone who can read the workflow logs (for public repositories, anyone at all) can decode what is printed and recover the secret.

This query reports `run` steps using a Bash shell where a secret (`${{ secrets.* }}`, `${{ toJSON(secrets) }}` or `${{ github.token }}`, used inline, through an environment variable, or through a shell variable assigned from one) is piped into an encoding command (`base64`, `base32`, `basenc`, `xxd`, `od`, `hexdump`, `rev`, `uuencode`, `openssl base64` or `openssl enc -base64`) whose output reaches the log, that is, it is not redirected to a file (with `>` or an output option such as `base64 -o`), captured in a variable or command substitution, or consumed by another command. Decoding commands such as `base64 --decode` or `xxd -r` are not reported.

## Known limitations

Variable assignments are ordered by their source line, not by shell control flow. Assignments inside functions or loops may execute in a different order than their source lines. Pipeline source attribution recognizes `curl` as a command that does not forward secret arguments to stdout; the output behavior of other commands is not modeled.

An input redirection (`base64 < file`) that replaces the pipe is recognized for every stage. A file operand that replaces the pipe is recognized only for `base64`, `base32`, `basenc` (`base64 file`) and `openssl` (`-in file`), so for other encoders such as `xxd file` the pipe is assumed to be the input. An assignment to an environment variable earlier in the script replaces its secret value for the statements after it, even when the assignment only runs in some branches.

A command between the secret and the encoder that destroys the secret, for example a hash such as `sha256sum` or encryption with a key, stops the query from reporting the statement. Only `tee`, `tr`, `cat` and `fold` are treated as keeping the data recoverable. Redirecting the output of the whole script with `exec >` is recognized, and so is the body of a here-document, which is data and not a command. Other ways of redirecting output are not modeled.

Decoding is not reported because restoring a certificate or key from a secret, as in `echo "$CERT_B64" | base64 --decode -o cert.p12`, is a routine step. Printing the decoded value to the log is a leak that this query does not find.

## Recommendation

Do not print secrets, or values derived from secrets, to the workflow log. If an encoded form of a secret is needed, capture it in a variable and register it with the `::add-mask::` workflow command before using it, and pass it to the consuming command through a file or standard input instead of printing it.

## Example

The following workflow prints the hexadecimal encoding of a secret. Masking does not apply to the encoded value, so the secret is exposed:

```yaml
- name: Get secret
  env:
    SUPER_SECRET: ${{ secrets.SUPER_SECRET }}
  run: echo "$SUPER_SECRET" | xxd -p
```

The encoded value should instead be masked and consumed without printing it:

```yaml
- name: Use secret
  env:
    SUPER_SECRET: ${{ secrets.SUPER_SECRET }}
  run: |
    ENCODED=$(echo "$SUPER_SECRET" | base64 -w0)
    echo "::add-mask::$ENCODED"
    echo "$ENCODED" | docker login -u user --password-stdin
```

## References

- GitHub Docs: [Using secrets in GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions).
- GitHub Docs: [Masking a value in a log](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#masking-a-value-in-a-log).
- Common Weakness Enumeration: [CWE-532](https://cwe.mitre.org/data/definitions/532.html).
