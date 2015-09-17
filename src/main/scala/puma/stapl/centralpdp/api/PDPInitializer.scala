package puma.stapl.centralpdp.api

import javax.servlet.ServletContextListener
import javax.servlet.ServletContextEvent
import puma.stapl.centralpdp.CentralStaplPDP

class PDPInitializer extends ServletContextListener {

  def contextDestroyed(e: ServletContextEvent) {
    //do nothing?
  }
  
  def contextInitialized(e: ServletContextEvent) {
    val pdp = CentralStaplPDP
    assert(pdp != null && pdp.isInstanceOf[CentralStaplPDP.type])
  }
  
}