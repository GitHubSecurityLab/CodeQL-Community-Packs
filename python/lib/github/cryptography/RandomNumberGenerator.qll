private import semmle.python.ApiGraphs
private import semmle.python.Concepts
private import semmle.python.dataflow.new.DataFlow

abstract class RandomNumberGeneratorSinks extends DataFlow::Node { }

class OsRandom extends RandomNumberGeneratorSinks {
  OsRandom() {
    exists(DataFlow::Node call |
      // https://docs.python.org/3/library/os.html#os.getrandom
      call = API::moduleImport("os").getMember("getrandom").getACall() and
      this = call
    )
  }
}

class PyRandom extends RandomNumberGeneratorSinks {
  PyRandom() {
    exists(DataFlow::Node call |
      (
        // https://docs.python.org/3/library/random.html#random.random
        call = API::moduleImport("random").getMember("random").getACall()
        or
        // https://docs.python.org/3/library/random.html#random.randbytes
        call = API::moduleImport("random").getMember("randbytes").getACall()
      ) and
      this = call
    )
  }
}

class PyUuid extends RandomNumberGeneratorSinks {
    PyUuid() {
        exists(DataFlow::Node call |
            call = API::moduleImport("uuid").getMember("uuid1").getACall() or
            call = API::moduleImport("uuid").getMember("uuid3").getACall() and
            this = call
        )
    }
}
