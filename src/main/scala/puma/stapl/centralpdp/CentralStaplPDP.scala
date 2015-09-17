package puma.stapl.centralpdp

import stapl.core.pdp.RequestCtx
import stapl.core.pdp.PDP
import grizzled.slf4j.Logging
import org.joda.time.LocalDateTime
import stapl.core.pdp.AttributeFinder
import puma.stapl.pip.SubjectAttributeFinderModule
import org.apache.thrift.transport.TServerTransport
import org.apache.thrift.transport.TServerSocket
import org.apache.thrift.transport.TTransportException
import org.apache.thrift.server.TServer
import org.apache.thrift.server.TThreadPoolServer
import puma.rmi.pdp.mgmt.CentralPUMAPDPMgmtRemote
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.ObjectWriter
import puma.util.timing.TimerFactory
import com.fasterxml.jackson.core.JsonProcessingException
import com.codahale.metrics.graphite.GraphiteReporter
import com.codahale.metrics.graphite.Graphite
import java.net.InetSocketAddress
import java.util.concurrent.TimeUnit
import com.codahale.metrics.MetricFilter
import java.io.PrintWriter
import java.io.FileNotFoundException
import java.io.UnsupportedEncodingException
import stapl.core.Result
import stapl.core.Attribute
import stapl.core.ConcreteValue
import stapl.core.AttributeType
import stapl.core.Bool
import stapl.core.Number
import stapl.core.String
import stapl.core.DateTime
import stapl.core.AttributeContainerType
import stapl.core.RESOURCE
import stapl.core.SUBJECT
import stapl.core.ACTION
import stapl.core.ENVIRONMENT
import stapl.core.Permit
import stapl.core.Deny
import stapl.core.NotApplicable
import stapl.core.SimpleAttribute
import stapl.core.ListAttribute
import puma.stapl.util.PolicyAssembler
import scala.collection.mutable
import scala.collection.mutable.Buffer
import stapl.core.AbstractPolicy
import org.apache.commons.io.FileUtils
import java.io.File
import java.io.IOException
import scala.util.Try
import scala.util.Success
import scala.util.Failure
import scala.util.Success
import org.apache.commons.cli.BasicParser
import org.apache.commons.cli.CommandLineParser
import org.apache.commons.cli.Options
import org.apache.commons.cli.HelpFormatter
import org.apache.commons.cli.ParseException
import java.rmi.registry.LocateRegistry
import java.rmi.RemoteException
import java.rmi.server.UnicastRemoteObject
import puma.rest.domain.ObjectType
import puma.rest.domain.AttributeValue
import puma.rest.domain.DataType
import puma.rest.domain.Multiplicity
import puma.rest.domain.ResponseType

@throws[IOException]
object CentralStaplPDP extends Logging {
  
  lazy val policyDir: String = {
    val property = System.getProperty("puma.centralpdp.policydir")
    info(s"property puma.centralpdp.policydir = $property")
    property
  }
  
  
  final val TIMER_NAME = "centralpumapdp.evaluate"
  
  final val CENTRAL_PUMA_POLICY_ID = "central-puma-policy"

  final val GLOBAL_PUMA_POLICY_ID = "global-puma-policy"
  
  
  private var status: String = "NOT INITIALIZED"
  
  // TODO preliminary implementation
  protected var pdp: PDP = _
  
  
  private def initializePDP() {
    identifiers ++= getDeployedTenantPolicies()
    PolicyAssembler.getGlobalPolicy(policyDir, identifiers) match {
      case Success(policy) =>
        initPDP(policy)
        status = "OK"
        info("Initialized global policy")
      case Failure(e: FileNotFoundException) => 
        error("Application policy file not found")
        status = "APPLICATION POLICY FILE NOT FOUND"
        throw e
      case Failure(e: Throwable) => 
        error("Could not initialize global policy", e)
        throw e
    }
  }
  
  def centralPUMAPolicyFilename: String = policyDir + CENTRAL_PUMA_POLICY_ID + ".stapl"

  
  /*private lazy val _pdp = new PDP({
    import stapl.core._
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
  })*/
  
  def evaluate(list: java.util.List[AttributeValue]): ResponseType = {
    val timerCtx = TimerFactory.getInstance().getTimer(getClass(), TIMER_NAME).time()
    
    import scala.collection.JavaConverters._
    val attributes = list.asScala
    
    val result = try{
      pdp.evaluate(toRequest(attributes)) match {
        case Result(Permit, _, _) => ResponseType.PERMIT
        case Result(Deny, _, _) => ResponseType.DENY
        case Result(NotApplicable, _, _) => ResponseType.NOT_APPLICABLE
      }
    } catch {
      case e: Exception => 
        debug(s"Exception thrown during evaluation: $e", e)
        ResponseType.INDETERMINATE
    }
    
    timerCtx.stop()
    result
  }
  
  private def toRequest(attributes: Seq[AttributeValue]): RequestCtx = {
    var subject, action, resource : Option[String] = None
    val convertedAttributes: Seq[(Attribute, ConcreteValue)] = 
      for(attr <- attributes) yield {
        if(attr.getId() == "id") {
          if(subject.isEmpty && attr.getObjectType() == ObjectType.SUBJECT) 
            subject = Some(attr.getStringValues().get(0))
          else if(action.isEmpty && attr.getObjectType() == ObjectType.ACTION) 
            action = Some(attr.getStringValues().get(0))
          else if(resource.isEmpty && attr.getObjectType() == ObjectType.RESOURCE) 
            resource = Some(attr.getStringValues().get(0))
        }
        if(attr.getMultiplicity() == Multiplicity.ATOMIC)
          SimpleAttribute(toACT(attr.getObjectType()), attr.getId(), toAType(attr.getDataType())) -> toConcreteValue(attr)
        else
          ListAttribute(toACT(attr.getObjectType()), attr.getId(), toAType(attr.getDataType())) -> toConcreteValue(attr)
      }
    val request = new RequestCtx(subject.getOrElse(""), action.getOrElse(""), resource.getOrElse(""))
    request.allAttributes ++= convertedAttributes
    request
  }
  
  private def toAType(dataType: DataType): AttributeType = dataType match {
    case DataType.BOOLEAN => Bool
    case DataType.DOUBLE => Number
    case DataType.INTEGER => Number
    case DataType.STRING => String
    case DataType.DATETIME => DateTime
  }
  
  private def toACT(typ: ObjectType): AttributeContainerType = typ match {
    case ObjectType.SUBJECT => SUBJECT
    case ObjectType.RESOURCE => RESOURCE
    case ObjectType.ACTION => ACTION
    case ObjectType.ENVIRONMENT => ENVIRONMENT
  }
  
  private def toConcreteValue(value: AttributeValue): ConcreteValue = {
    import scala.collection.JavaConverters._
    
    if (value.getMultiplicity() == Multiplicity.ATOMIC)
      value.getDataType() match {
        case DataType.BOOLEAN => value.getBooleanValues().get(0).asInstanceOf[Boolean]
        case DataType.DOUBLE => value.getDoubleValues().get(0).asInstanceOf[Double]
        case DataType.INTEGER => value.getIntValues().get(0).asInstanceOf[Int]
        case DataType.STRING => value.getStringValues().get(0)
        case DataType.DATETIME => new LocalDateTime(value.getDatetimeValues().get(0))
      }
    else
      value.getDataType() match {
        case DataType.BOOLEAN => value.getBooleanValues().asScala.asInstanceOf[Seq[Boolean]]
        case DataType.DOUBLE => value.getDoubleValues().asScala.asInstanceOf[Seq[Double]]
        case DataType.INTEGER => value.getIntValues().asScala.asInstanceOf[Seq[Int]]
        case DataType.STRING => value.getStringValues().asScala
        case DataType.DATETIME => value.getDatetimeValues().asScala.map(date => new LocalDateTime(date))
      }
  }
  
  
  /* CentralPUMAPDPMgmtRemote implementation */
  
  def getCentralPUMAPolicy(): String = {
    try {
      FileUtils.readFileToString(new File(centralPUMAPolicyFilename))
    } catch {
      case e: IOException =>
        warn("IOException when reading Central PUMA PDP policy file", e)
        "IOException"
    }
  }
  
  private val identifiers: Buffer[String] = Buffer.empty[String]
  
  def getIdentifiers(): java.util.List[String] = {
    import scala.collection.JavaConverters._
    identifiers.asJava
  }
  
  private  def getDeployedTenantPolicies(): Seq[String] = {
    val currentDirectory = new File(this.policyDir)
    currentDirectory.listFiles() flatMap { next =>
      if (next.isFile() && next.getName().endsWith(".stapl")) {
        Try {
          next.getName().substring(0, next.getName().indexOf(".")).toLong
        } match {
          case Success(long) => Some(long.toString)
          case Failure(_) => None
        }
      } else None
    }
  }
  
  def getStatus(): String = status
  
  def loadCentralPUMAPolicy(policy: String) {
    val writer =
      try {
        new PrintWriter(centralPUMAPolicyFilename, "UTF-8")
      } catch {
        case e: FileNotFoundException => 
          error(
            "Application policy file not found when writing new Central PUMA PDP policy",
            e)
          return
        case e: UnsupportedEncodingException =>
          error(
            "Unsupported encoding when writing new Central PUMA PDP policy",
            e)
          return
      }
    writer.print(policy)
    writer.close()
    info("Succesfully reloaded Central PUMA PDP policy")
    this.reload()
  }
  
  private def constructFilename(id: String): String = this.policyDir + id + ".stapl"
  
  def loadTenantPolicy(tenantId: String, policy: String) {
    try {
      val writer = new PrintWriter(
          this.constructFilename(tenantId), "UTF-8")
      writer.print(policy)
      writer.close()
    } catch {
      case e: FileNotFoundException => 
        error(
          "Application policy file not found when writing new Central PUMA PDP policy",
           e)
        return
      case e: UnsupportedEncodingException =>
        error(
          "Unsupported encoding when writing new Central PUMA PDP policy",
          e)
        return
    }
    // Register the tenant
    this.registerPolicy(tenantId)
  }
  
  private def registerPolicy(tenantId: String) {
    // Rewrite the central policy and make sure there is a reference to the
    // added policy
    if (!this.identifiers.contains(tenantId))
      this.identifiers += tenantId
    
    reload(
      () => info("Succesfully deployed new tenant policy " + this.constructFilename(tenantId)),
      warn("Unable to deploy policy", _)
    )
  }
  
  private def reload(onSucces: () => Unit, onFailure: Throwable => Unit) { 
    val policy = PolicyAssembler.getGlobalPolicy(policyDir, identifiers) match {
      case Success(p) => p
      case Failure(e) => onFailure(e); return
    }
    
    onSucces()
    
    initPDP(policy)
  }
  
  private def initPDP(policy: AbstractPolicy) {
    val finder = new AttributeFinder
    finder += new SubjectAttributeFinderModule
    pdp = new PDP(policy, finder)
  }
  
  def reload() {
    this.reload(() => (), e => ())
  }
  
  def getMetrics(): String = {
    val mapper: ObjectMapper = new ObjectMapper()
    val writer: ObjectWriter = mapper.writerWithDefaultPrettyPrinter()
    try {
      writer.writeValueAsString(TimerFactory.getInstance().getMetricRegistry())
    } catch {
      case e: JsonProcessingException =>
        warn("Exception on JSON encoding of metrics", e)
        ""
    }
  }
  
  private var reporter: Option[GraphiteReporter] = None
  
  def resetMetrics() {
    TimerFactory.getInstance().resetAllTimers()

    // connect metrics to the Graphite server
    reporter.foreach{ _.stop() }
    
    
    val graphite = new Graphite(new InetSocketAddress("172.16.4.2", 2003))
    reporter = Some(GraphiteReporter
        .forRegistry(TimerFactory.getInstance().getMetricRegistry())
        .prefixedWith("puma-central-pdp")
        .convertRatesTo(TimeUnit.SECONDS)
        .convertDurationsTo(TimeUnit.MILLISECONDS)
        .filter(MetricFilter.ALL).build(graphite))
    reporter.foreach{ _.start(10, TimeUnit.SECONDS) }
  }
  
  // start the initialization process of this PDP
  initializePDP()
}