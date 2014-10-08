package puma.stapl.centralpdp

import puma.thrift.pdp.RemotePDPService
import puma.thrift.pdp.AttributeValueP
import puma.thrift.pdp.ResponseTypeP
import stapl.core._
import stapl.core.pdp.RequestCtx
import stapl.core.pdp.PDP
import grizzled.slf4j.Logging
import puma.thrift.pdp.DataTypeP
import puma.thrift.pdp.ObjectTypeP
import puma.thrift.pdp.MultiplicityP
import org.joda.time.LocalDateTime
import stapl.core.pdp.AttributeFinder
import puma.stapl.pip.SubjectAttributeFinderModule
import org.apache.thrift.transport.TServerTransport
import org.apache.thrift.transport.TServerSocket
import org.apache.thrift.transport.TTransportException
import org.apache.thrift.server.TServer
import org.apache.thrift.server.TThreadPoolServer

class CentralStaplPDP extends RemotePDPService.Iface with Logging {

  // TODO preliminary implementation
  protected def pdp: PDP = _pdp
  
  private lazy val _pdp = new PDP({
    val (subject, action, resource, _) = BasicPolicy.containers
    resource.type_ = SimpleAttribute("type", String)
    resource.creating_tenant = SimpleAttribute("creating-tenant", String)
    resource.owning_tenant = SimpleAttribute("owning-tenant", String)
    subject.tenant = ListAttribute(String)
    subject.assigned_tenants = ListAttribute("subject:assigned_tenants", String)
    subject.region = ListAttribute("subject:region", String)
    
    val centralPolicy =
      Policy("central-puma-policy") := when (resource.type_ === "document") apply DenyOverrides to(
        Policy("reading-deleting") := when (action.id === "read" | action.id === "delete") apply DenyOverrides to(
          Rule("1") := deny iff (!(resource.creating_tenant in subject.tenant)),
          Rule("default-permit:1") := permit
        ),
        Policy("creating") := when (action.id === "create") apply DenyOverrides to(
          Rule("default-permit:99") := permit
        )
      )
    
    val tenant3 =
      Policy("tenantsetid:3") := when ("3" in subject.tenant) apply DenyOverrides to(
        Policy("large-bank:read") := when (action.id === "read" & resource.type_ === "document") apply PermitOverrides to(
          Rule("191") := permit iff (resource.owning_tenant in subject.assigned_tenants),
          Rule("193") := deny
        ),
        Policy("large-bank:send") := when (action.id === "send" & resource.type_ === "document") apply PermitOverrides to(
          Rule("193") := permit
        )
      )
    
    val tenant4 =
      Policy("tenantsetid:4") := when ("4" in subject.tenant) apply DenyOverrides to(
        Policy("press-agency") := apply DenyOverrides to(
          Rule("press-agency:1") := deny iff (!("Europe" in subject.region)),
          Rule("press-agency:2") := permit
        )
      )
    
    Policy("global-puma-policy") := apply DenyOverrides to (
      centralPolicy,
      tenant3,
      tenant4
    )
  }, 
  {
    val finder = new AttributeFinder
    finder += new SubjectAttributeFinderModule
    finder
  })
  
  override def evaluateP(list: java.util.List[AttributeValueP]): ResponseTypeP = {
    import scala.collection.JavaConverters._
    val attributes = list.asScala
    
    try{
      pdp.evaluate(toRequest(attributes)) match {
        case Result(Permit, _) => ResponseTypeP.PERMIT
        case Result(Deny, _) => ResponseTypeP.DENY
        case Result(NotApplicable, _) => ResponseTypeP.NOT_APPLICABLE
      }
    } catch {
      case e: Exception => 
        debug(s"Exception thrown during evaluation: $e", e)
        ResponseTypeP.INDETERMINATE
    }
  }
  
  private def toRequest(attributes: Seq[AttributeValueP]): RequestCtx = {
    var subject, action, resource : Option[String] = None
    val convertedAttributes: Seq[((String, AttributeContainerType), ConcreteValue)] = 
      for(attr <- attributes) yield {
        if(attr.getId() == "id") {
          if(subject.isEmpty && attr.getObjectType() == ObjectTypeP.SUBJECT) 
            subject = Some(attr.getStringValues().get(0))
          else if(action.isEmpty && attr.getObjectType() == ObjectTypeP.ACTION) 
            action = Some(attr.getStringValues().get(0))
          else if(resource.isEmpty && attr.getObjectType() == ObjectTypeP.RESOURCE) 
            resource = Some(attr.getStringValues().get(0))
        }
        (attr.getId(), toACT(attr.getObjectType())) -> toConcreteValue(attr)
      }
    val request = new RequestCtx(subject.getOrElse(""), action.getOrElse(""), resource.getOrElse(""))
    request.allAttributes ++= convertedAttributes
    request
  }
  
  private def toACT(typ: ObjectTypeP): AttributeContainerType = typ match {
    case ObjectTypeP.SUBJECT => SUBJECT
    case ObjectTypeP.RESOURCE => RESOURCE
    case ObjectTypeP.ACTION => ACTION
    case ObjectTypeP.ENVIRONMENT => ENVIRONMENT
  }
  
  private def toConcreteValue(value: AttributeValueP): ConcreteValue = {
    import scala.collection.JavaConverters._
    
    if (value.getMultiplicity() == MultiplicityP.ATOMIC)
      value.getDataType() match {
        case DataTypeP.BOOLEAN => value.getBooleanValues().get(0).asInstanceOf[Boolean]
        case DataTypeP.DOUBLE => value.getDoubleValues().get(0).asInstanceOf[Double]
        case DataTypeP.INTEGER => value.getIntValues().get(0).asInstanceOf[Int]
        case DataTypeP.STRING => value.getStringValues().get(0)
        case DataTypeP.DATETIME => new LocalDateTime(value.getDatetimeValues().get(0))
      }
    else
      value.getDataType() match {
        case DataTypeP.BOOLEAN => value.getBooleanValues().asScala.asInstanceOf[Seq[Boolean]]
        case DataTypeP.DOUBLE => value.getDoubleValues().asScala.asInstanceOf[Seq[Double]]
        case DataTypeP.INTEGER => value.getIntValues().asScala.asInstanceOf[Seq[Int]]
        case DataTypeP.STRING => value.getStringValues().asScala
        case DataTypeP.DATETIME => value.getDatetimeValues().asScala.map(date => new LocalDateTime(date))
      }
  }
}

// TODO merge this with XACML version?
object Main extends Logging {
  
  private val THRIFT_PDP_PORT = 9091
  
  def main(args: Array[String]) {
    
    val pdp = new CentralStaplPDP
    
    new Thread(new Runnable() {     
      @Override
      def run() {
        val pdpProcessor: RemotePDPService.Processor[CentralStaplPDP] = new RemotePDPService.Processor[CentralStaplPDP](pdp)
        val pdpServerTransport: TServerTransport =
          try {
            new TServerSocket(THRIFT_PDP_PORT)
          } catch {
            case e: TTransportException => 
              e.printStackTrace()
              return
          }
        val pdpServer: TServer = new TThreadPoolServer(new TThreadPoolServer.Args(pdpServerTransport).processor(pdpProcessor))
        info("Setting up the Thrift PDP server on port " + THRIFT_PDP_PORT)
        pdpServer.serve()
      }
    }).start()
  }
  
}