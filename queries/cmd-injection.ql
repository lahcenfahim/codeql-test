/**
 * @name Command injection
 * @description Executing user-controlled commands can lead to command injection vulnerabilities
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id py/command-injection-custom
 * @tags security
 *       external/cwe/cwe-078
 */

import python
import semmle.python.security.dataflow.CommandInjectionQuery
import DataFlow::PathGraph

from CommandInjectionFlow::PathNode source, CommandInjectionFlow::PathNode sink
where CommandInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This command depends on a $@.", source.getNode(), "user-provided value"
