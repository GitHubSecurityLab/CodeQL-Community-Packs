/**
 * Provides default sources, sinks and sanitizers for reasoning about
 * Chrome API injection vulnerabilities, as well as extension points for
 * adding your own.
 */
import javascript
private import browserextension.BrowserAPI
private import semmle.javascript.security.dataflow.XssThroughDomCustomizations::XssThroughDom as XssThroughDom

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



/**
 * Sink for chrome.tabs.update() which may allow an allow an arbitrary redirect if
 * user input is used.
 */
class Update extends Sink {
    Update() {exists (DataFlow::CallNode c | c = tabsRef().getAMethodCall("update") and this = c.getArgument(c.getNumArgument()-1))}
  }

/*
 * A sink for chrome extensions that may allow an attacker to download a file, or make an arbitrary request
 */

 class DownloadsDangerous extends Sink {
  DownloadsDangerous() { this = downloadsRef().getAMethodCall("download").getArgument(0) }
}

/*
 * A sink for chrome extensions that may allow an attacker to remove a file.
 */

class DownloadsRemoveFile extends Sink {
  DownloadsRemoveFile() { this = downloadsRef().getAMethodCall("removeFile").getArgument(0) }
}



/** 
 * Requires reading the return value
 * Sink
 * chrome.cookies.getAll()
 */
class GetCookie extends Sink {
  GetCookie() {cookiesRef().getAMethodCall(["get","getAll"]).getArgument(0) = this}
}

/** 
 *
 * Sink
 * chrome.history.search()
 */
class AddHistory extends Sink {
  AddHistory() {historyRef().getAMethodCall("addUrl").getArgument(0) = this}
}

/** 
 * Requires reading the return value
 * Sink
 * chrome.history.search()
 */
class SearchHistory extends Sink {
  SearchHistory() {historyRef().getAMethodCall("search").getArgument(0) = this}
}

/** 
 * Sink
 * chrome.history.deleteUrl/deleteRange
 */
class Delete extends Sink {
  Delete() {historyRef().getAMethodCall(["deleteUrl","deleteRange"]).getArgument(0) = this}
}

/**
 * chrome.bookmarks.remove/update()
 */
class UpdateBookmarks extends DataFlow::Node {
  UpdateBookmarks() {bookmarksRef().getAMethodCall(["remove", "update"]).getArgument([0,1]) = this}
}

/**
 * chrome.browsingData.removePasswords()
 */
class RemoveBrowsingData extends Sink {
  RemoveBrowsingData() {this = browsingDataRef().getAMethodCall("removePasswords").getArgument(0)}

}

/**
 * chrome.windows.create()
 */
class CreateWindows extends Sink {
  CreateWindows() {this = windowsRef().getAMethodCall("create").getArgument(0)}

}

/**
 * chrome.windows.remove()
 */
class RemoveWindows extends Sink {
  RemoveWindows() {this = windowsRef().getAMethodCall("create").getArgument(0)}

}




 //Firefox only
 //browser.management.removePasswords()
// class ManagementEnable extends Sink {
//   ManagementEnable() {managementRef().getAMethodCall("setEnabled").getArgument([0,1])}

// }

/** 
 * SINK WITH NO ARGUMENTS
 * Requires reading the return value
 * chrome.bookmarks.getTree() this has no arguments
 */

 class GetTreeBookmarks extends DataFlow::Node {
  GetTreeBookmarks() {bookmarksRef().getAMethodCall("getTree") = this}
}




/** 
 * Source
 * chrome.runtime.onConnectExternal.addListener
 */

 class OnConnectExternalProxy extends Source instanceof OnConnectExternal {
  OnConnectExternalProxy() { exists(Runtime r, DataFlow::ParameterNode p| r.getAPropertyRead("onConnectExternal").(DataFlow::SourceNode).getAMethodCall("addListener").getArgument(0).asExpr().(Function).getParameter(0) = p.getParameter() and  p =  this)}
}

/** 
* Source
* chrome.runtime.onMessageExternal.addListener
*/

class OnMessageExternalProxy extends Source instanceof OnMessageExternal {
  OnMessageExternalProxy() { exists(Runtime r, DataFlow::ParameterNode p | r.getAPropertyRead("onMessageExternal").(DataFlow::SourceNode).getAMethodCall("addListener").getArgument(0).asExpr().(Function).getParameter(0) = p.getParameter() and this = p)}
}

/** 
* Source
* noisy, use as needed
*/

//class XSSDOMProxy extends Source instanceof XssThroughDom::Source{}

class RemoteFlowSourceProxy extends Source instanceof RemoteFlowSource{}


class BrowserStep extends DataFlow::SharedFlowStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    (exists (DataFlow::ParameterNode p |
      pred instanceof SendMessage and
      succ = p and 
         p.getParameter() instanceof AddListener
    ))
  }
}

class ReturnStep extends DataFlow::SharedFlowStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    (exists (DataFlow::ParameterNode p |
      succ instanceof SendMessageReturnValue and
      pred = p.getAnInvocation().getArgument(0) and 
         p.getParameter() instanceof AddListenerReturn
    ))
  }
}

class AwaitStep extends DataFlow::SharedFlowStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ){
    succ.asExpr() instanceof AwaitExpr and pred.asExpr() = succ.asExpr().(AwaitExpr).getOperand()
  }
}

}