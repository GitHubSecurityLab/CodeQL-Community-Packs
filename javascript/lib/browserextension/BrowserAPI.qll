import javascript

/**
 * Provides classes modeling dangerous sinks for browser extension APIs.
 * Currently supports browser.download, browser.contentsettings, browser.tabs and chrome.runtime
 */

module Browser {
  /**
   * A data flow node that should be considered a source of the `browser/chrome` object.
   *
   * Can be subclassed to add additional such nodes.
   */
  abstract class Range extends DataFlow::Node { }

  class DefaultRange extends Range {
    DefaultRange() { this = [DataFlow::globalVarRef("browser"), DataFlow::globalVarRef("chrome")] }
  }
}

/**
 * Gets a direct reference to the `browser` object.
 */
DataFlow::SourceNode browserSource() { result instanceof Browser::Range }

/**
 * Gets a reference to the `browser` object.
 */
private DataFlow::SourceNode browserRef(DataFlow::TypeTracker t) {
  t.start() and
  result instanceof Browser::Range
  or
  exists(DataFlow::TypeTracker t2 | result = browserRef(t2).track(t2, t))
}

/**
 * Gets a reference to the 'browser' object.
 */
DataFlow::SourceNode browserRef() { result = browserRef(DataFlow::TypeTracker::end()) }

module TabsSource {
  /**
   * A data flow node that should be considered a source of the browser `tabs` object.
   *
   * Can be subclassed to add additional such nodes.
   */
  abstract class Range extends DataFlow::Node { }

  class DefaultRange extends Range {
    DefaultRange() { this = browserRef().getAPropertyRead("tabs") }
  }
}

/** Gets a reference to a browser `tabs` object. */
private DataFlow::SourceNode tabsRef(DataFlow::TypeTracker t) {
  t.start() and
  result = tabsSource()
  or
  t.startInProp("tabs") and
  result = [browserSource()]
  or
  exists(DataFlow::TypeTracker t2 | result = tabsRef(t2).track(t2, t))
}

/** Gets a reference to a browser `tabs` object. */
DataFlow::SourceNode tabsRef() { result = tabsRef(DataFlow::TypeTracker::end()) }

/**
 * Gets a direct reference to the browser `tabs` object.
 */
DataFlow::SourceNode tabsSource() { result instanceof TabsSource::Range }


module WindowsSource {
  /**
   * A data flow node that should be considered a source of the browser `windows` object.
   *
   * Can be subclassed to add additional such nodes.
   */
  abstract class Range extends DataFlow::Node { }

  class DefaultRange extends Range {
    DefaultRange() { this = browserRef().getAPropertyRead("windows") }
  }
}

/** Gets a reference to a browser `tabs` object. */
private DataFlow::SourceNode windowsRef(DataFlow::TypeTracker t) {
  t.start() and
  result = windowsSource()
  or
  t.startInProp("windows") and
  result = [browserSource()]
  or
  exists(DataFlow::TypeTracker t2 | result = windowsRef(t2).track(t2, t))
}

/** Gets a reference to a browser `tabs` object. */
DataFlow::SourceNode windowsRef() { result = windowsRef(DataFlow::TypeTracker::end()) }

/**
 * Gets a direct reference to the browser `tabs` object.
 */
DataFlow::SourceNode windowsSource() { result instanceof WindowsSource::Range }

module CookiesSource {
    /**
     * A data flow node that should be considered a source of the browser `cookies` object.
     *
     * Can be subclassed to add additional such nodes.
     */
    abstract class Range extends DataFlow::Node { }
  
    class DefaultRange extends Range {
      DefaultRange() { this = browserRef().getAPropertyRead("cookies") }
    }
  }
  
  /** Gets a reference to a browser `cookies` object. */
  private DataFlow::SourceNode cookiesRef(DataFlow::TypeTracker t) {
    t.start() and
    result = cookiesSource()
    or
    t.startInProp("cookies") and
    result = [browserSource()]
    or
    exists(DataFlow::TypeTracker t2 | result = cookiesRef(t2).track(t2, t))
  }
  
  /**  
   * Gets a reference to a browser `cookies` object.
  */
  DataFlow::SourceNode cookiesRef() { result = cookiesRef(DataFlow::TypeTracker::end()) }
  
  /**
   * Gets a direct reference to the browser `cookies` object.
   */
  DataFlow::SourceNode cookiesSource() { result instanceof CookiesSource::Range }



  module BrowsingDataSource {
    /**
     * A data flow node that should be considered a source of the browser `browsingData` object.
     *
     * Can be subclassed to add additional such nodes.
     */
    abstract class Range extends DataFlow::Node { }
  
    class DefaultRange extends Range {
      DefaultRange() { this = browserRef().getAPropertyRead("browsingData") }
    }
  }
  
  /** Gets a reference to a browser `browsingData` object. */
  private DataFlow::SourceNode browsingDataRef(DataFlow::TypeTracker t) {
    t.start() and
    result = browsingDataSource()
    or
    t.startInProp("browsingData") and
    result = [browserSource()]
    or
    exists(DataFlow::TypeTracker t2 | result = browsingDataRef(t2).track(t2, t))
  }
  
  /**  
   * Gets a reference to a browser `browsingData` object.
  */
  DataFlow::SourceNode browsingDataRef() { result = browsingDataRef(DataFlow::TypeTracker::end()) }
  
  /**
   * Gets a direct reference to the browser `browsingData` object.
   */
  DataFlow::SourceNode browsingDataSource() { result instanceof BrowsingDataSource::Range }






  module BookmarksSource {
    /**
     * A data flow node that should be considered a source of the browser `bookmarks` object.
     *
     * Can be subclassed to add additional such nodes.
     */
    abstract class Range extends DataFlow::Node { }
  
    class DefaultRange extends Range {
      DefaultRange() { this = browserRef().getAPropertyRead("bookmarks") }
    }
  }
  
  /** Gets a reference to a browser `bookmarks` object. */
  private DataFlow::SourceNode bookmarksRef(DataFlow::TypeTracker t) {
    t.start() and
    result = bookmarksSource()
    or
    t.startInProp("bookmarks") and
    result = [browserSource()]
    or
    exists(DataFlow::TypeTracker t2 | result = bookmarksRef(t2).track(t2, t))
  }
  
  /**  
   * Gets a reference to a browser `bookmarks` object.
  */
  DataFlow::SourceNode bookmarksRef() { result = bookmarksRef(DataFlow::TypeTracker::end()) }
  
  /**
   * Gets a direct reference to the browser `bookmarks` object.
   */
  DataFlow::SourceNode bookmarksSource() { result instanceof BookmarksSource::Range }






  module HistorySource {
    /**
     * A data flow node that should be considered a source of the browser `history` object.
     *
     * Can be subclassed to add additional such nodes.
     */
    abstract class Range extends DataFlow::Node { }
  
    class DefaultRange extends Range {
      DefaultRange() { this = browserRef().getAPropertyRead("history") }
    }
  }
  
  /** Gets a reference to a browser `history` object. */
  private DataFlow::SourceNode historyRef(DataFlow::TypeTracker t) {
    t.start() and
    result = historySource()
    or
    t.startInProp("history") and
    result = [browserSource()]
    or
    exists(DataFlow::TypeTracker t2 | result = historyRef(t2).track(t2, t))
  }
  
  /**  
   * Gets a reference to a browser `history` object.
  */
  DataFlow::SourceNode historyRef() { result = historyRef(DataFlow::TypeTracker::end()) }
  
  /**
   * Gets a direct reference to the browser `history` object.
   */
  DataFlow::SourceNode historySource() { result instanceof HistorySource::Range }



  module StorageSource {
    /**
     * A data flow node that should be considered a source of the browser `storage` object.
     *
     * Can be subclassed to add additional such nodes.
     */
    abstract class Range extends DataFlow::Node { }
  
    class DefaultRange extends Range {
      DefaultRange() { this = browserRef().getAPropertyRead("storage") }
    }
  }
  
  /** Gets a reference to a browser `storage` object. */
  private DataFlow::SourceNode storageRef(DataFlow::TypeTracker t) {
    t.start() and
    result = storageSource()
    or
    t.startInProp("storage") and
    result = [browserSource()]
    or
    exists(DataFlow::TypeTracker t2 | result = storageRef(t2).track(t2, t))
  }
  
  /**  
   * Gets a reference to a browser `storage` object.
  */
  DataFlow::SourceNode storageRef() { result = storageRef(DataFlow::TypeTracker::end()) }
  
  /**
   * Gets a direct reference to the browser `storage` object.
   */
  DataFlow::SourceNode storageSource() { result instanceof StorageSource::Range }






  module StorageTypeSource {
    /**
     * A data flow node that should be considered a source of the browser.storage `type` object.
     *
     * Can be subclassed to add additional such nodes.
     */
    abstract class Range extends DataFlow::Node { }
  
    class DefaultRange extends Range {
      DefaultRange() { this = storageRef().getAPropertyRead(["local", "managed", "session"]) }
    }
  }
  
  /** Gets a reference to a browser `storage` object. */
  private DataFlow::SourceNode storagetypeRef(DataFlow::TypeTracker t) {
    t.start() and
    result = storagetypeSource()
    or
    t.startInProp(["local", "managed", "session"]) and
    result = [storageSource()]
    or
    exists(DataFlow::TypeTracker t2 | result = storagetypeRef(t2).track(t2, t))
  }
  
  /**  
   * Gets a reference to a browser.storage `type` object.
  */
  DataFlow::SourceNode storagetypeRef() { result = storagetypeRef(DataFlow::TypeTracker::end()) }
  
  /**
   * Gets a direct reference to the browser.storage `type` object.
   */
  DataFlow::SourceNode storagetypeSource() { result instanceof StorageTypeSource::Range }

  module TopSitesSource {
    /**
     * A data flow node that should be considered a source of the browser `topSites` object.
     *
     * Can be subclassed to add additional such nodes.
     */
    abstract class Range extends DataFlow::Node { }
  
    class DefaultRange extends Range {
      DefaultRange() { this = browserRef().getAPropertyRead("topSites") }
    }
  }
  
  /** Gets a reference to a browser `topSites` object. */
  private DataFlow::SourceNode topSitesRef(DataFlow::TypeTracker t) {
    t.start() and
    result = topSitesSource()
    or
    t.startInProp("topSites") and
    result = [browserSource()]
    or
    exists(DataFlow::TypeTracker t2 | result = topSitesRef(t2).track(t2, t))
  }
  
  /**  
   * Gets a reference to a browser `topSites` object.
  */
  DataFlow::SourceNode topSitesRef() { result = topSitesRef(DataFlow::TypeTracker::end()) }
  
  /**
   * Gets a direct reference to the browser `topSites` object.
   */
  DataFlow::SourceNode topSitesSource() { result instanceof TopSitesSource::Range }

/**
 * Sink for chrome.tabs.executeScript() which may allow an allow arbitrary javascript execution.
 */
class ExecuteScript extends DataFlow::Node {
  ExecuteScript() { exists( DataFlow::CallNode c | 
    c = tabsRef().getAMethodCall("executeScript") | (this = c.getArgument(0) and c.getNumArgument() = 1) 
    or
    (this = c.getArgument(1) and c.getNumArgument() = 2 ) )}
}

module DownloadSource {
  /**
   * A data flow node that should be considered a source of the chrome `download` object.
   *
   * Can be subclassed to add additional such nodes.
   */
  abstract class Range extends DataFlow::Node { }

  class DefaultRange extends Range {
    DefaultRange() { this = browserRef().getAPropertyRead("downloads") }
  }
}

private DataFlow::SourceNode downloadsRef(DataFlow::TypeTracker t) {
  t.start() and
  result = downloadsSource()
  or
  t.startInProp("downloads") and
  result = [browserSource()]
  or
  exists(DataFlow::TypeTracker t2 | result = downloadsRef(t2).track(t2, t))
}

 /**  
   * Gets a reference to a browser `downloads` object.
  */
DataFlow::SourceNode downloadsRef() { result = downloadsRef(DataFlow::TypeTracker::end()) }

 /**
   * Gets a direct reference to the browser `downloads` object.
   */
DataFlow::SourceNode downloadsSource() { result instanceof TabsSource::Range }



module ContentSettingsSource {
  /**
   * A data flow node that should be considered a source of the DOM `contentsettings` object.
   *
   * Can be subclassed to add additional such nodes.
   */
  abstract class Range extends DataFlow::Node { }

  class DefaultRange extends Range {
    DefaultRange() {
      exists(string propName | this = browserRef().getAPropertyRead(propName) |
        propName = ["contentSettings"]
      )
    }
  }
}

private DataFlow::SourceNode contentSettingsRef(DataFlow::TypeTracker t) {
  t.start() and
  result = contentSettingsSource()
  or
  t.startInProp("contentSettings") and
  result = [DataFlow::globalObjectRef(), browserSource()]
  or
  exists(DataFlow::TypeTracker t2 | result = contentSettingsRef(t2).track(t2, t))
}

/**
 * Gets a reference to a `contentSettings` object.
 */

DataFlow::SourceNode contentSettingsRef() { result = contentSettingsRef(DataFlow::TypeTracker::end()) }

/**
 * Gets a direct reference to the `contentSettings` object.
 */

DataFlow::SourceNode contentSettingsSource() { result instanceof ContentSettingsSource::Range }

/**
 * A specific content setting for chrome extensions.
 * Ex: chrome.contentsettings.cookies
 */
module ContentSettingsSettingsSource {
  /**
   * A data flow node that should be considered a source of the chrome.contentsettings `property` object.
   *
   * Can be subclassed to add additional such nodes.
   */
  abstract class Range extends DataFlow::Node { }

  class DefaultRange extends Range {
    DefaultRange() {
      exists(string propName | this = contentSettingsRef().getAPropertyRead(propName) |
        propName =
          [
            "cookies", "images", "javascript", "location", "popups", "notifications", "microphone",
            "camera", "automaticDownloads"
          ]
      )
    }
  }
}

/**
 * A specific content setting for chrome extensions.
 * Ex: chrome.contentsettings.cookies
 */
private DataFlow::SourceNode contentSettingsSettingsRef(DataFlow::TypeTracker t) {
  t.start() and
  result = contentSettingsSettingsSource()
  or
  t.startInProp([
      "cookies", "images", "javascript", "location", "popups", "notifications", "microphone",
      "camera", "automaticDownloads"
    ]) and
  result = [contentSettingsSource()]
  or
  exists(DataFlow::TypeTracker t2 | result = contentSettingsSettingsRef(t2).track(t2, t))
}

/**
 * Gets a reference to a `chrome.contentSetting.property` object.
 */
DataFlow::SourceNode contentSettingsSettingsRef() {
  result = contentSettingsSettingsRef(DataFlow::TypeTracker::end())
}

/**
 * Gets a direct reference to the `chrome.contentSetting.property` object.
 */
DataFlow::SourceNode contentSettingsSettingsSource() {
  result instanceof ContentSettingsSettingsSource::Range
}


/**
 * chrome.runtime dataflow node
 */
class Runtime extends DataFlow::SourceNode {
  Runtime() { this = browserRef().getAPropertyRead("runtime").(DataFlow::SourceNode) }
}

/**
 * chrome.runtime.onMessage.AddListner()
 */
class AddListener extends Parameter {
  AddListener() {
    exists(Runtime r |
      r.getAPropertyRead("onMessage").(DataFlow::SourceNode).getAMethodCall("addListener").getArgument(0).asExpr().(Function).getParameter(0) = this
    )
  }
}

/**
 * chrome.runtime.onMessage.AddListner()
 */
class AddListenerReturn extends Parameter {
  AddListenerReturn() {
    exists(Runtime r |
      r.getAPropertyRead("onMessage").(DataFlow::SourceNode).getAMethodCall("addListener").getArgument(0).asExpr().(Function).getParameter(2) = this
    )
  }
}

/**
 * chrome.runtime.sendMessage()
 */
class SendMessage extends DataFlow::Node {
  SendMessage() { exists(Runtime r | (r.getAMethodCall("sendMessage").getArgument(1) = this and  r.getAMethodCall("sendMessage").getNumArgument() = 3)
                                      or  (r.getAMethodCall("sendMessage").getArgument(0) = this and r.getAMethodCall("sendMessage").getNumArgument() < 3 ))}
}

/**
 * chrome.runtime.sendMessage() return value
 */
class SendMessageReturnValue extends DataFlow::SourceNode {
  SendMessageReturnValue() { (browserRef().getAPropertyRead("runtime").(DataFlow::SourceNode).getAMethodCall("sendMessage") = this)}
}



/** 
 * Source
 * chrome.runtime.onConnectExternal.addListener
 */

class OnConnectExternal extends DataFlow::Node {
    OnConnectExternal() { exists(Runtime r, DataFlow::ParameterNode p| r.getAPropertyRead("onConnectExternal").(DataFlow::SourceNode).getAMethodCall("addListener").getArgument(0).asExpr().(Function).getParameter(0) = p.getParameter() and  p =  this)}
}

/** 
 * Source
 * chrome.runtime.onConnectExternal.addListener
 */

 class OnConnectExternalFunction extends DataFlow::Node {
  OnConnectExternalFunction() { exists(Runtime r | r.getAPropertyRead("onConnectExternal").(DataFlow::SourceNode).getAMethodCall("addListener") = this)}
}

/** 
 * Source
 * chrome.runtime.onMessageExternal.addListener
 */

 class OnMessageExternal extends DataFlow::Node {
    OnMessageExternal() { exists(Runtime r, DataFlow::ParameterNode p | r.getAPropertyRead("onMessageExternal").(DataFlow::SourceNode).getAMethodCall("addListener").getArgument(0).asExpr().(Function).getParameter(0) = p.getParameter() and this = p)}
}

 /** 
 * Source
 * chrome.runtime.onMessageExternal.addListener sender parameter
 */

 class OnMessageExternalSender extends DataFlow::ParameterNode {
  OnMessageExternalSender() { exists(Runtime r, DataFlow::ParameterNode pp | r.getAPropertyRead("onMessageExternal").(DataFlow::SourceNode).getAMethodCall("addListener").getArgument(0).asExpr().(Function).getParameter(1) = pp.getParameter() and this = pp)}
}



//Return value is important, but how to model output?
/** 
 * Sink
 * chrome.topSites.get()
 */
class GetTopSites extends DataFlow::Node {
    GetTopSites() {topSitesRef().getAMethodCall("get") = this}
}





