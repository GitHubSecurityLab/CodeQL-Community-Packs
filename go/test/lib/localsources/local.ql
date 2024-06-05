import go
import ghsl.Utils
import ghsl.LocalSources

query predicate remoteSources(DataFlow::ExprNode node) { node instanceof RemoteFlowSource::Range }

query predicate localSources(DataFlow::ExprNode node) { node instanceof LocalSources::Range }
