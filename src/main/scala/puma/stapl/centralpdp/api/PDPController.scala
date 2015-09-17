package puma.stapl.centralpdp.api

import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseBody
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestBody
import puma.stapl.centralpdp.CentralStaplPDP
import java.util.{Map => JMap, List => JList}
import puma.thrift.pdp.AttributeValueP
import puma.thrift.pdp.ResponseTypeP
import puma.rest.domain.Request
import puma.rest.domain.ResponseType
import puma.rest.domain.Status
import puma.rest.domain.Policy
import puma.rest.domain.Identifiers
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.http.HttpStatus

@Controller
@RequestMapping(value = Array("/"))
class PDPController {

  import scala.collection.JavaConverters._
  
  @ResponseBody
  @RequestMapping(value = Array("/evaluate"), method = Array(RequestMethod.POST), consumes=Array("application/json"), produces=Array("application/json"))
  def evaluate(@RequestBody request: Request): ResponseType = 
    CentralStaplPDP.evaluate(request.getAttributes)
  
  @ResponseBody
  @RequestMapping(value = Array("/status"), method = Array(RequestMethod.GET), produces=Array("application/json"))
  def getStatus(): Status = new Status(CentralStaplPDP.getStatus())
  
  @ResponseStatus(value = HttpStatus.OK)
  @RequestMapping(value = Array("/policy"), method = Array(RequestMethod.PUT), consumes=Array("application/json"))
  def loadCentralPUMAPolicy(@RequestBody policy: Policy) {
    CentralStaplPDP.loadCentralPUMAPolicy(policy.getPolicy)
  }
  
  @ResponseBody
  @RequestMapping(value = Array("/policy"), method = Array(RequestMethod.GET), produces=Array("application/json"))
  def getCentralPUMAPolicy(): Policy = 
    new Policy(CentralStaplPDP.getCentralPUMAPolicy())

  @ResponseStatus(value = HttpStatus.OK)
  @RequestMapping(value = Array("/{tenantIdentifier}/policy"), method = Array(RequestMethod.PUT), consumes=Array("application/json"))
  def loadTenantPolicy(@PathVariable tenantIdentifier: String, @RequestBody policy: Policy) {
    CentralStaplPDP.loadTenantPolicy(tenantIdentifier, policy.getPolicy)
  }
  
  @ResponseBody
  @RequestMapping(value = Array("/ids"), method = Array(RequestMethod.GET), produces=Array("application/json"))
  def getIdentifiers(): Identifiers = 
    new Identifiers(CentralStaplPDP.getIdentifiers())
  
}