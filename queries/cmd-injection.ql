/**
 * @name Command Injection (Python)
 * @description Detects possible command injection vulnerabilities in Python
 * @kind problem
 * @id py/command-injection
 * @tags security
 */

import python
import semmle.python.security.TaintTracking

class UserInput extends TaintTracking::Source {
  UserInput() { this.isParameter() or this.isInput() }
}

class CommandSink extends TaintTracking::Sink {
  CommandSink() { exists(Call c |
    c.getCallee().getName() in ["system", "popen", "run", "call"] and
    this = c.getArgument(0)
  ) }
}

// Si une donnée utilisateur atteint un sink, c’est une alerte
from UserInput src, CommandSink sink
where TaintTracking::localFlow(src, sink)
select sink, "Potential command injection: user input reaches system command"
