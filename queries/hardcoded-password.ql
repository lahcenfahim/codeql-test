/**
 * @name Hardcoded password
 * @description Détecte les mots de passe codés en dur
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id custom/hardcoded-password
 * @tags security
 */

import python

from Assign assign, Name var, StrConst value
where
  assign.getTarget(0) = var and
  assign.getValue() = value and
  var.getId().toLowerCase().matches("%password%") and
  value.getS().length() > 3
select assign, "HIGH: Mot de passe codé en dur détecté: " + var.getId()