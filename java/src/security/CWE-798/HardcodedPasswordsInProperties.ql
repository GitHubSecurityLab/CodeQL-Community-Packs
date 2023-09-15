/**
 * @name Hard-coded password field
 * @description Hard-coding a password string may compromise security.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision low
 * @id java/hardcoded-password-field
 * @tags security
 *       external/cwe/cwe-798
 */

import java
import semmle.code.configfiles.ConfigFiles

// Fork of:
//  https://github.com/github/codeql/blob/main/java/ql/src/experimental/semmle/code/java/frameworks/CredentialsInPropertiesFile.qll
private string possibleSecretName() {
  result =
    [
      "%password%", "%passwd%", "%account%", "%accnt%", "%credential%", "%token%", "%secret%",
      "%access%key%"
    ]
}

private string possibleEncryptedSecretName() { result = ["%hashed%", "%encrypted%", "%crypt%"] }

/** Holds if the value is not cleartext credentials. */
bindingset[value]
predicate isNotCleartextCredentials(string value) {
  value = "" // Empty string
  or
  value.length() < 5 // Typical credentials are no less than 6 characters
  or
  value.matches("% %") // Sentences containing spaces
  or
  value.regexpMatch(".*[^a-zA-Z\\d]{3,}.*") // Contain repeated non-alphanumeric characters such as a fake password pass**** or ????
  or
  value.matches("@%") // Starts with the "@" sign
  or
  value.regexpMatch("\\$\\{.*\\}") // Variable placeholder ${credentials}
  or
  value.matches("%=") // A basic check of encrypted credentials ending with padding characters
  or
  value.matches("ENC(%)") // Encrypted value
  // or
  // Could be a message property for UI display or fake passwords, e.g. login.password_expired=Your current password has expired.
  // value.toLowerCase().matches(possibleSecretName())
}

class ConfigPropertiesCredencials extends ConfigPair {
  ConfigPropertiesCredencials() {
    // Looks for matches to possible secret / password names
    this.getNameElement().getName().trim().toLowerCase().matches(possibleSecretName()) and
    // Make sure the name isn't encrypted
    not this.getNameElement().getName().trim().toLowerCase().matches(possibleEncryptedSecretName()) and
    // Make sure the content isn't encrypted
    not isNotCleartextCredentials(this.getValueElement().getValue().trim())
  }

  string getName() { result = this.getNameElement().getName().trim() }

  string getValue() { result = this.getValueElement().getValue().trim() }

  string getConfigDesc() {
    result =
      "Plaintext credentials " + this.getName() + " have cleartext value '" + this.getValue() +
        "' in properties file"
  }
}

from ConfigPropertiesCredencials conf
select conf.getValueElement(), conf.getConfigDesc()
