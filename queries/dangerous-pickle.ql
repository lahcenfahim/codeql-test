/**
 * @name Dangerous pickle usage
 * @description Détecte pickle.loads() qui permet l'exécution de code
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id custom/dangerous-pickle
 * @tags security
 */

import python

from Call call, Attribute attr
where 
  call.getFunc() = attr and
  attr.getObject().(Name).getId() = "pickle" and
  attr.getName() = "loads"
select call, "CRITICAL: Utilisation dangereuse de pickle.loads() détectée!"