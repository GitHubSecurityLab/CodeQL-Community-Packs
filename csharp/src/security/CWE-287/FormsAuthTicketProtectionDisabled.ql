/**
 * @name Forms authentication ticket protection disabled
 * @description Setting 'protection' to 'None' on the forms authentication element disables both
 *              encryption and validation of the forms authentication ticket, so an attacker can
 *              forge or tamper with the ticket and impersonate any user.
 * @kind problem
 * @id githubsecuritylab/cs/forms-auth-ticket-protection-disabled
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @tags security
 *       experimental
 *       external/cwe/cwe-287
 */

import csharp
import semmle.code.asp.WebConfig

/**
 * Holds if `file` is a `Web.config` file or a `Web.<name>.config` transformation file. A copy
 * under another name, such as `Web - Copy.config`, and an application configuration, such as
 * `Program.exe.config`, are not used for the authentication settings of a web application.
 */
private predicate isWebConfigFile(XmlFile file) {
  exists(string name | name = file.getBaseName().toLowerCase() |
    name = "web.config" or name.matches("web.%.config")
  )
}

/**
 * Holds if forms authentication is the authentication mode of the `<authentication>` element
 * that contains `forms`. The default mode is `Windows`, and forms authentication is only active
 * in `Forms` mode.
 */
private predicate isFormsAuthenticationMode(FormsElement forms) {
  forms.getParent().(XmlElement).getAttribute("mode").getValue() = "Forms"
}

from FormsElement forms, XmlAttribute protection
where
  isWebConfigFile(forms.getFile()) and
  isFormsAuthenticationMode(forms) and
  protection = forms.getAttribute("protection") and
  // The runtime rejects other spellings, such as `none` or ` None `, as an invalid configuration.
  protection.getValue() = "None"
select protection,
  "The forms authentication ticket is neither encrypted nor validated because 'protection' is set to 'None'."
