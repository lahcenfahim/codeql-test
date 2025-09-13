/**
 * @name Command Injection
 * @description Detects potential command injection vulnerabilities in Python code
 * @kind problem
 * @id py/command-injection
 * @tags security
 */

import python
import semmle.code.python.dataflow.DataFlow

// Source : données venant de l'utilisateur
class UserInputSource extends DataFlow::SourceNode {
  UserInputSource() { this.getASource().getType().hasName("str") }
}

// Sink : fonctions d'exécution de commandes système
class CommandSink extends DataFlow::SinkNode {
  CommandSink() { 
    exists(Call c | 
      c.getCallee().getName() in ["system", "popen", "run", "call"] and
      this = c.getArgument(0)
    )
  }
}

// Détection : flux de données utilisateur vers sink
from Expr arg
where DataFlow::localFlow(UserInputSource(), CommandSink(arg))
select arg, "Potential command injection: user input reaches system command execution"
