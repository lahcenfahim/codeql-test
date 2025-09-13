/**
 * @name Injection de commandes simple
 * @description Détecte l'utilisation d'os.system avec input() directement
 * @kind problem
 * @problem.severity error
 * @id py/simple-command-injection
 * @tags security
 */

import python

from Call call
where
  // Cherche les appels à os.system()
  call.getFunc().(Attribute).getAttr() = "system" and
  call.getFunc().(Attribute).getValue().(Name).getId() = "os" and
  
  // Vérifie si l'argument contient un appel à input()
  call.getArg(0).(Call).getFunc().(Name).getId() = "input"

select call, "Utilisation dangereuse d'os.system() avec input() utilisateur"
