private import go

module LocalSources {
  private import semmle.go.dataflow.DataFlow
  private import semmle.go.dataflow.TaintTracking
  private import semmle.go.Scopes
  
  abstract class Range extends DataFlow::Node { }

// ========== Sources ==========

abstract class Sources extends DataFlow::Node { }

// ----------------------------------------------------
// Used for finding Selections or Calls for Go imports 
// ----------------------------------------------------

//class UseOfGoImports extends Sources { 
  //UseOfGoImports () {
    //exists ( ValueEntity read, 
             //DataFlow::Package pkg | 
             //read.getScope().getEntity(_) = pkg.getScope().getEntity(_)
             //and ( this.toString().regexpMatch("selection of.*")
              //or this.toString().regexpMatch("call to .*") )
    //)
  //}
//}

// ----------------------------------------------------

class OsCmd extends LocalSources::Range {
  OsCmd() {
    exists ( ValueEntity read, 
      DataFlow::Package pkg | 
      read.getScope().getEntity(_) = pkg.getScope().getEntity(_)
      and this.toString() = "selection of Run"
    ) 
  }
}

class OsExec extends LocalSources::Range {
  OsExec() {
    exists ( ValueEntity read, 
             DataFlow::Package pkg | 
             read.getScope().getEntity(_) = pkg.getScope().getEntity(_)
             and this.toString() = "selection of Command"
    )
  }
}

class OsArgs extends LocalSources::Range { 
  OsArgs() {
    exists ( ValueEntity read, 
             DataFlow::Package pkg | 
             read.getScope().getEntity(_) = pkg.getScope().getEntity(_)
             and this.toString() = "selection of Args"
    )
  }
}

// Not currently working (need a test case)
//class OsGetenv extends Sources, DataFlow::CallNode {
  //OsGetenv() {
    //// https://pkg.go.dev/os#Getenv
    //this.getTarget().hasQualifiedName(package("os", ""), "Getenv")
    //or
    //// https://pkg.go.dev/os#Environ
    //this.getTarget().hasQualifiedName(package("os", ""), "Environ")
  //}
//}

  // https://pkg.go.dev/flag
class Flag extends LocalSources::Range {
    Flag() {
      exists ( ValueEntity read, 
               DataFlow::Package pkg | 
               read.getScope().getEntity(_) = pkg.getScope().getEntity(_)
               and 
               ( this.toString() = "selection of String"
               or this.toString() = "selection of Parse" )
      )
    }
}
}