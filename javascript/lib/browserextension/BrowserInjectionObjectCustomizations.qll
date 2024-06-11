/**
 * Provides default sources, sinks and sanitizers for reasoning about
 * Chrome API injection vulnerabilities, as well as extension points for
 * adding your own.
 */
import javascript
private import browserextension.BrowserAPI

module BrowserInjection {

  private import DataFlow::FlowLabel
  /**
   * A data flow source for Chrome API injection vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { 



    DataFlow::FlowLabel getFlowLabel() { result = "BrowserSource" }
  }

  /**
   * A data flow sink for Chrome API injection vulnerabilities.
   */
  abstract class Sink extends DataFlow::Node {
  }

  class RemoteFlowSourceAsSource extends Source instanceof RemoteFlowSource { }



/**
 * Sink for chrome.tabs.update() which may allow an allow an arbitrary redirect if
 * user input is used.
 */
class Update extends Sink {
    Update() {exists (DataFlow::CallNode c | c = tabsRef().getAMethodCall("update") and this = c.getArgument(c.getNumArgument()-1))}
  }

  class BrowserStep extends DataFlow::SharedFlowStep {
    override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
      (exists (DataFlow::ParameterNode p |
        pred instanceof SendMessage and
        succ = p and 
           p.getParameter() instanceof AddListener
      ))
    }
  }



/*
 * A sink for chrome extensions that may allow an attacker to remove a file.
 */

// class DownloadsRemoveFile extends Sink {
//   DownloadsRemoveFile() { this = downloadsRef().getAMethodCall("removeFile") }
// }

/** 
 * Sink
 * chrome.bookmarks.getTree() this has no arguments
 */

 class GetTreeBookmarks extends DataFlow::Node {
  GetTreeBookmarks() {bookmarksRef().getAMethodCall("getTree") = this}
}




/** 
 * Source
 * chrome.runtime.onConnectExternal.addListener
 */

 class OnConnectExternalProxy extends Sink instanceof OnConnectExternal {
  OnConnectExternalProxy() { exists(Runtime r, DataFlow::ParameterNode p| r.getAPropertyRead("onConnectExternal").(DataFlow::SourceNode).getAMethodCall("addListener").getArgument(0).asExpr().(Function).getParameter(0) = p.getParameter() and  p =  this)}
}

/** 
* Source
* chrome.runtime.onMessageExternal.addListener
*/

class OnMessageExternalProxy extends Sink instanceof OnMessageExternal {
  OnMessageExternalProxy() { exists(Runtime r, DataFlow::ParameterNode p | r.getAPropertyRead("onMessageExternal").(DataFlow::SourceNode).getAMethodCall("addListener").getArgument(0).asExpr().(Function).getParameter(0) = p.getParameter() and this = p)}
}





//Problems

class StorageGet extends Sink {
  StorageGet() {storagetypeRef().getAMethodCall("get").getAnArgument() = this}
}

class StorageSet extends Sink {
  StorageSet() {storagetypeRef().getAMethodCall("set").getAnArgument()= this}
}

/**
 * A sink for chrome extensions
 *
 * If a user controlled value flows into chrome.contentsettings.[contentsetting].set() an attacker
 * may be able to set arbitrary settings.
 */
class SetContentSettings extends Sink {
  SetContentSettings() { this = contentSettingsSettingsRef().getAMethodCall("set").getAnArgument() }
}

/**
 * A sink for chrome extensions
 *
 * If a user controlled value flows into chrome.contentsettings.[contentsetting].get() an attacker
 * may be able to get arbitrary settings.
 */
class GetContentSettings extends Sink {
    GetContentSettings() { this = contentSettingsSettingsRef().getAMethodCall("get").getAnArgument() }
  }


}