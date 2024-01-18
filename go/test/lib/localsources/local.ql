import go
import ghsl.Utils
import ghsl.LocalSources

query predicate remoteSources(DataFlow::ExprNode node) { node instanceof UntrustedFlowSource }

query predicate localSources(DataFlow::ExprNode node) { node instanceof LocalSources::Range }
