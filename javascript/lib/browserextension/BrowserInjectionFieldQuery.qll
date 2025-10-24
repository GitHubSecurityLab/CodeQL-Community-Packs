 import javascript
 private import browserextension.BrowserInjectionFieldCustomizations::BrowserInjection
 private import semmle.javascript.security.dataflow.XssThroughDomCustomizations::XssThroughDom as XssThroughDom

 //private import semmle.javascript.security.dataflow.DomBasedXssCustomizations
 //private import semmle.javascript.security.dataflow.XssThroughDomCustomizations::XssThroughDom as XssThroughDom

 //private import semmle.javascript.security.dataflow.CodeInjectionCustomizations

   module Config implements DataFlow::ConfigSig {

    predicate isSource(DataFlow::Node source) {
       source instanceof Source
     }

    predicate isSink(DataFlow::Node sink) {
       sink instanceof Sink
     }

    additional predicate isAdditionalLoadStep(DataFlow::Node pred, DataFlow::Node succ, string prop) {
       (pred = succ) and
       ((pred instanceof Update and prop = ["url", "openerTabId"])
       or
       (pred instanceof DownloadsDangerous and prop = ["body", "conflictAction","filename", "url", "method"])
       or
       (pred instanceof Delete and prop = ["startTime", "endTime", "url"])
       //or
       //(pred instanceof SetContentSettings and succ instanceof SetContentSettings and prop = any(string s))
       //or
       //(pred instanceof GetContentSettings and succ instanceof GetContentSettings and prop = any(string s))
        //(pred instanceof StorageSet and succ instanceof StorageSet and prop = any(string s))
       //or
       //(pred instanceof SearchHistory and prop = any(string s))
       or
       (pred instanceof GetCookie and prop = ["domain", "firstPartyDomain", "name", "url", "session", "path", "storeId"])
       or
       (pred instanceof UpdateBookmarks and prop= ["title", "url"])
       or
       (pred = succ and pred instanceof RemoveBrowsingData and prop = ["cookieStoreId", "hostnames", "originTypes", "since"])
       or
       (pred = succ and pred instanceof AddHistory and prop = ["url"])
       or
       (pred = succ and pred instanceof CreateWindows and prop = ["url"]))
     }
   }

   module ConfigFlow = TaintTracking::Global<Config>;
