/**
 * @name Remote Sources
 * @kind problem
 * @problem.severity note
 * @precision low
 * @id js/debugging/remote-sources
 * @tags debugging
 */

 import javascript

 // ==========================================================================
//     Helper Predicates
// ==========================================================================

/**
 * Filter results to a specific file and line number
 * 
 *  **Examples:**
 * 
 *  ```
 *  filterByLocation(sources, "db.js", 1)
 *  // or we don't care about the line numbers
 *  filterByLocation(sources, "db.js", _)
 *  ```
 */
predicate filterByLocation(DataFlow::Node node, string relative_path, int linenumber) {
    node.getLocation().getFile().getRelativePath() = relative_path and
    node.getLocation().getStartLine() = linenumber
  }
  
  
  // ==========================================================================
  //     Sources
  // ==========================================================================
  
  /**
   * All Sources (Remote and Local)
   */
  final class AllSources extends RemoteSources, LocalSources { }
  
  /**
   * Remote Sources (HTTP frameworks, etc)
   */
  class RemoteSources extends ThreatModelSource {
    RemoteSources() { this.getThreatModel() = "remote" }
  }
  
  /**
   * Local Sources (CLI arguments, Filesystem, etc)
   */
  class LocalSources extends ThreatModelSource {
    LocalSources() { this.getThreatModel() = "local" }
  }

 from RemoteSources sources
//  where
//    // Filter results to a specific file
//    filterByLocation(sources, "app.js", _)
 select sources, "Remote Sources"