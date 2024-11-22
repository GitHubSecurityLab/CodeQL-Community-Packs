/**
 * @name OnMessageExternalNoVerify
 * @description Use of OnMessage Add Listener Without a Check For the ID, Origin, or URL may result in attacker data being implicitly trusted. CodeQL does not include 
 * manifest.json in default builds, explicitly include it in builds to use this query. This query only checks local reads, so read elsewhere may not be found.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.1
 * @precision high
 * @id js/browser-missing-origin-check
 * @tags security
 */

 import javascript
 import browserextension.BrowserAPI
 import DataFlow
 import semmle.javascript.JSON

 predicate is_externally_connectable(JsonValue res){
    res = any(JsonValue v).getPropValue("externally_connectable")
 }

 from OnMessageExternalSender omes, string l
 where not exists(PropRead r | DataFlow::localFlowStep*(omes, r.getBase())and r.getPropertyName() = ["id", "origin", "url"]) and
 (exists(JsonValue sl | is_externally_connectable(sl) and l = sl.toString()) or 
 not exists(JsonValue sl | is_externally_connectable(sl)) and l = "all installed extensions")
 select omes, "Unchecked external messages with user-controlled input from " + l