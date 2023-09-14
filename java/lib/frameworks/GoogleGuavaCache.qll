import semmle.code.java.dataflow.TaintTracking

module GuavaCache {
  class TypeCacheBuilder extends RefType {
    TypeCacheBuilder() { this.hasQualifiedName("com.google.common.cache", "CacheBuilder") }
  }

  class TypeLoadingCache extends RefType {
    TypeLoadingCache() { this.hasQualifiedName("com.google.common.cache", "LoadingCache") }
  }

  class GetFromCacheMethod extends Method {
    GetFromCacheMethod() {
      this.getDeclaringType().getASourceSupertype*() instanceof TypeLoadingCache and
      (this.getName() = "get" or this.getName() = "getUnchecked")
    }
  }

  class BuildCacheLoaderMethod extends Method {
    BuildCacheLoaderMethod() {
      this.getDeclaringType().getASourceSupertype*() instanceof TypeCacheBuilder and
      this.getName() = "build"
    }
  }

  /**
   * Taint step from the `get` operation to the loader
   * CacheLoader<String, String> loader;
   * loader = new CacheLoader<String, String>() {
   *
   * @Override public String load(String key) {
   *         return key.toUpperCase(); // N2
   *     }
   * };
   * LoadingCache<String, String> cache;
   * cache = CacheBuilder.newBuilder().build(loader);
   * assertEquals("HELLO", cache.getUnchecked("doo")); // N1
   */
  class LoadCacheItemTaintStep extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
      exists(MethodAccess ma1, MethodAccess ma2, VarAccess va |
        ma1.getMethod() instanceof GetFromCacheMethod and
        ma2.getMethod() instanceof BuildCacheLoaderMethod and
        exists(Method m |
          ma2.getArgument(0).getType().(RefType).getAMethod() = m and
          m.getName() = "load" and
          m.getAParameter() = va.getVariable() and
          n1.asExpr() = ma1.getArgument(0) and
          n2.asExpr() = va
        )
      )
    }
  }
}
