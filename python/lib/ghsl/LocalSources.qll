private import python

// ========== Sources ==========
module LocalSources {
  private import semmle.python.dataflow.new.DataFlow
  private import semmle.python.dataflow.new.TaintTracking
  private import semmle.python.Concepts
  private import semmle.python.dataflow.new.BarrierGuards
  private import semmle.python.ApiGraphs

  abstract class Range extends DataFlow::Node { }

  // Standard Input from user
  class STDInputSources extends LocalSources::Range {
    STDInputSources() {
      exists(DataFlow::Node call |
        (
          // v = input("Input?")
          call = API::builtin("input").getACall()
          or
          // https://docs.python.org/3/library/fileinput.html
          call = API::moduleImport("fileinput").getMember("input").getACall()
        ) and
        call.getScope().inSource() and
        this = call
      )
    }
  }

  // Command Line Arguments
  class CommandLineArgumentsSources extends LocalSources::Range {
    CommandLineArgumentsSources() {
      exists(DataFlow::Node call |
        (
          // v = sys.args[1]
          call = API::moduleImport("sys").getMember("argv").getAValueReachableFromSource()
          or
          // parser = argparse.ArgumentParser(__name__)
          // ...
          // arguments = parser.parse_args()
          // v = arguments.t     # user input
          exists(DataFlow::CallCfgNode args |
            args =
              API::moduleImport("argparse")
                  .getMember("ArgumentParser")
                  .getACall()
                  .getAMethodCall("parse_args")
          |
            call = args
            or
            call = args.getAnAttributeRead()
          )
        ) and
        call.getScope().inSource() and
        this = call
      )
    }
  }

  // Local Environment Variables
  class EnviromentVariablesSources extends LocalSources::Range {
    EnviromentVariablesSources() {
      exists(DataFlow::Node call |
        (
          // os.getenv('abc')
          call = API::moduleImport("os").getMember("getenv").getACall()
          or
          // a = os.environ['abc']
          call.asCfgNode().(SubscriptNode).getObject() =
            API::moduleImport("os").getMember("environ").getAValueReachableFromSource().asCfgNode()
          or
          // g = os.environ.get('abc')
          call = API::moduleImport("os").getMember("environ").getMember("get").getACall()
        ) and
        call.getScope().inSource() and
        this = call
      )
    }
  }

  // Local File Reads
  class FileReadSource extends LocalSources::Range {
    FileReadSource() {
      exists(DataFlow::Node call |
        (
          // https://docs.python.org/3/library/functions.html#open
          // var = open('abc.txt')
          call = API::builtin("open").getACall().getAMethodCall(["read", "readline", "readlines"])
          or
          // https://docs.python.org/3/library/os.html#os.read
          call = API::moduleImport("os").getMember("read").getACall()
          or
          // json.load
          call = API::moduleImport(["json", "simplejson"]).getMember("load").getACall()
          or
          // yaml.load
          call =
            API::moduleImport("yaml")
                .getMember(["load", "load_all", "safe_load", "safe_load_all"])
                .getACall()
          or
          // msgpack.load
          call = API::moduleImport("msgpack").getMember("load").getACall()
          or
          // pickle.load
          // dill.load
          call =
            API::moduleImport(["cPickle", "_pickle", "pickle", "dill"]).getMember("load").getACall()
          or
          // pickle.Unpickler.load
          // dill.Unpickler.load
          call =
            API::moduleImport(["cPickle", "pickle", "dill"])
                .getMember("Unpickler")
                .getACall()
                .getAMethodCall("load")
          or
          // shelve.open
          call = API::moduleImport("shelve").getMember("open").getACall()
          or
          // numpy.loadtxt
          call = API::moduleImport("numpy").getMember(["loadtxt", "genfromtxt"]).getACall()
          or
          // csv
          call = API::moduleImport("csv").getMember(["reader", "DictReader"]).getACall()
          or
          // pandas.read_pickle
          // pandas.read_table
          // pandas.read_csv
          // pandas.read_fwf
          // pandas.read_excel
          // pandas.read_json
          // pandas.read_html
          // pandas.read_xml
          // pandas.read_hdf
          // pandas.read_feather
          // pandas.read_parquet
          // pandas.read_orc
          // pandas.read_sas
          // pandas.read_spss
          // pandas.read_sql_table
          // pandas.read_sql_query
          // pandas.read_sql
          // pandas.read_gbq
          // pandas.read_stata
          // generate call expressions for each of the above pandas functions including ExcelFile.parse and HDFStore.* that have to be handled separately
          call =
            API::moduleImport("pandas")
                .getMember([
                    "read_csv", "read_fwf", "read_excel", "read_json", "read_html", "read_xml",
                    "read_hdf", "read_feather", "read_parquet", "read_orc", "read_sas", "read_spss",
                    "read_sql_table", "read_sql_query", "read_sql", "read_gbq", "read_stata"
                  ])
                .getACall()
          or
          // pandas.ExcelFile.parse
          call =
            API::moduleImport("pandas").getMember("ExcelFile").getACall().getAMethodCall("parse")
          or
          // pandas.HDFStore.get
          // pandas.HDFStore.select
          // pandas.HDFStore.info
          // pandas.HDFStore.keys
          // pandas.HDFStore.groups
          // pandas.HDFStore.walk
          call =
            API::moduleImport("pandas")
                .getMember("HDFStore")
                .getACall()
                .getAMethodCall(["get", "select", "info", "keys", "groups", "walk"])
          or
          // polars.read_csv
          call =
            API::moduleImport("polars")
                .getMember(["read_csv", "read_csv_batched", "scan_csv"])
                .getACall()
          or
          // polars.read_ipc
          call =
            API::moduleImport("polars")
                .getMember(["read_ipc", "scan_ipc", "read_ipc_schema"])
                .getACall()
          or
          // polars.read_parquet, polars.scan_parquet, polars.read_parquet_schema
          call =
            API::moduleImport("polars")
                .getMember(["read_parquet", "scan_parquet", "read_parquet_schema"])
                .getACall()
          or
          // polars.read_sql
          call = API::moduleImport("polars").getMember("read_sql").getACall()
          or
          // polars.read_json, polars.read_ndjson, polars.scan_ndjson
          call =
            API::moduleImport("polars")
                .getMember(["read_json", "read_ndjson", "scan_ndjson"])
                .getACall()
          or
          // polars.read_avro
          call = API::moduleImport("polars").getMember("read_avro").getACall()
          or
          // polars.read_excel
          call = API::moduleImport("polars").getMember("read_excel").getACall()
          or
          // pyarrow.csv.read_csv
          // pyarrow.csv.open_csv
          // pyarrow.csv.CSVStreamingReader
          call =
            API::moduleImport("pyarrow")
                .getMember("csv")
                .getMember(["read_csv", "open_csv", "CSVStreamingReader"])
                .getACall()
          or
          // pyarrow.feather.read_feather
          // pyarrow.feather.read_table
          call =
            API::moduleImport("pyarrow")
                .getMember("feather")
                .getMember(["read_feather", "read_table"])
                .getACall()
          or
          // pyarrow.json.read_json
          call = API::moduleImport("pyarrow").getMember("json").getMember("read_json").getACall()
          or
          // pyarrow.parquet.ParquetDataset
          // pyarrow.parquet.ParquetFile
          // pyarrow.parquet.read_table
          // pyarrow.parquet.read_metadata
          // pyarrow.parquet.read_pandas
          // pyarrow.parquet.read_schema
          call =
            API::moduleImport("pyarrow")
                .getMember("parquet")
                .getMember([
                    "ParquetDataset", "ParquetFile", "read_table", "read_metadata", "read_pandas",
                    "read_schema"
                  ])
                .getACall()
        ) and
        this = call
      ) and
      this.getScope().inSource()
    }
  }
}
