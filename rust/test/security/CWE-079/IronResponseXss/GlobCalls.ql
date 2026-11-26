/**
 * Lists the calls of `glob_prelude.rs` that have no target. The queries recognize Iron by its names
 * because of them: if the extraction resolves these calls some day, this test changes and the file no
 * longer exercises the fallback.
 */

import rust

from Call call
where
  call.getLocation().getFile().getBaseName() = "glob_prelude.rs" and
  not exists(call.getStaticTarget())
select call.getLocation().getStartLine(), call.toString()
