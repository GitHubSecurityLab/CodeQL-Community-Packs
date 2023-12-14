private import semmle.python.ApiGraphs
private import semmle.python.Concepts
private import semmle.python.dataflow.new.DataFlow

module RandomNumberGenerator {
  abstract class Sinks extends DataFlow::Node { }

  class OsRandom extends Sinks {
    OsRandom() {
      exists(DataFlow::Node call |
        // https://docs.python.org/3/library/os.html#os.getrandom
        call = API::moduleImport("os").getMember("getrandom").getACall() and
        this = call
      )
    }
  }

  class PyRandom extends Sinks {
    PyRandom() {
      exists(DataFlow::Node call |
        // TODO: does `random.seed(_)` need to be static?
        // https://docs.python.org/3/library/random.html#random.random
        call =
          API::moduleImport("random")
              .getMember(["random", "randrange", "randint", "randbytes"])
              .getACall() and
        this = call
      )
    }
  }

  class PyUuid extends Sinks {
    PyUuid() {
      exists(DataFlow::Node call |
        call = API::moduleImport("uuid").getMember(["uuid1", "uuid3"]).getACall() and
        this = call
      )
    }
  }
}
