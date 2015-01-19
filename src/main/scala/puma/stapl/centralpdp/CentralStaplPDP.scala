package puma.stapl.centralpdp

import puma.thrift.pdp.RemotePDPService
import puma.thrift.pdp.AttributeValueP
import puma.thrift.pdp.ResponseTypeP
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

object CentralStaplPDP {
  final val TIMER_NAME = "centralpumapdp.evaluate"
  
  final val CENTRAL_PUMA_POLICY_ID = "central-puma-policy"

  final val GLOBAL_PUMA_POLICY_ID = "global-puma-policy"
}

@throws[IOException]
class CentralStaplPDP(policyDir: String) extends RemotePDPService.Iface with CentralPUMAPDPMgmtRemote with Logging {
  
  import CentralStaplPDP._
  
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
  
  override def evaluateP(list: java.util.List[AttributeValueP]): ResponseTypeP = {
    val timerCtx = TimerFactory.getInstance().getTimer(getClass(), TIMER_NAME).time()
    
    import scala.collection.JavaConverters._
    val attributes = list.asScala
    
    val result = try{
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
    
    timerCtx.stop()
    result
  }
  
  private def toRequest(attributes: Seq[AttributeValueP]): RequestCtx = {
    var subject, action, resource : Option[String] = None
    val convertedAttributes: Seq[(Attribute, ConcreteValue)] = 
      for(attr <- attributes) yield {
        if(attr.getId() == "id") {
          if(subject.isEmpty && attr.getObjectType() == ObjectTypeP.SUBJECT) 
            subject = Some(attr.getStringValues().get(0))
          else if(action.isEmpty && attr.getObjectType() == ObjectTypeP.ACTION) 
            action = Some(attr.getStringValues().get(0))
          else if(resource.isEmpty && attr.getObjectType() == ObjectTypeP.RESOURCE) 
            resource = Some(attr.getStringValues().get(0))
        }
        if(attr.getMultiplicity() == MultiplicityP.ATOMIC)
          SimpleAttribute(toACT(attr.getObjectType()), attr.getId(), toAType(attr.getDataType())) -> toConcreteValue(attr)
        else
          ListAttribute(toACT(attr.getObjectType()), attr.getId(), toAType(attr.getDataType())) -> toConcreteValue(attr)
      }
    val request = new RequestCtx(subject.getOrElse(""), action.getOrElse(""), resource.getOrElse(""))
    request.allAttributes ++= convertedAttributes
    request
  }
  
  private def toAType(dataType: DataTypeP): AttributeType = dataType match {
    case DataTypeP.BOOLEAN => Bool
    case DataTypeP.DOUBLE => Number
    case DataTypeP.INTEGER => Number
    case DataTypeP.STRING => String
    case DataTypeP.DATETIME => DateTime
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
  
  
  /* CentralPUMAPDPMgmtRemote implementation */
  
  override def getCentralPUMAPolicy(): String = {
    try {
      FileUtils.readFileToString(new File(centralPUMAPolicyFilename))
    } catch {
      case e: IOException =>
        warn("IOException when reading Central PUMA PDP policy file", e)
        "IOException"
    }
  }
  
  private val identifiers: Buffer[String] = Buffer.empty[String]
  
  override def getIdentifiers(): java.util.List[String] = {
    import scala.collection.JavaConverters._
    identifiers.asJava
  }
  
  private  def getDeployedTenantPolicies(): Seq[String] = {
    val currentDirectory = new File(this.policyDir)
    currentDirectory.listFiles() flatMap { next =>
      if (next.isFile() && !next.getName().endsWith("~")) {
        Try {
          next.getName().substring(0, next.getName().indexOf(".")).toLong
        } match {
          case Success(long) => Some(long.toString)
          case Failure(_) => None
        }
      } else None
    }
  }
  
  override def getStatus(): String = status
  
  override def loadCentralPUMAPolicy(policy: String) {
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
  
  override def loadTenantPolicy(tenantId: String, policy: String) {
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
  
  override def reload() {
    this.reload(() => (), e => ())
  }
  
  override def getMetrics(): String = {
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
  
  override def resetMetrics() {
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

// TODO merge this with XACML version?
object Main extends Logging {
  
  private val THRIFT_PDP_PORT = 9071
  private val RMI_REGISITRY_PORT = 2040
  private val CENTRAL_PUMA_PDP_RMI_NAME = "central-puma-pdp-stapl"
  
  def main(args: Array[String]) {
    
    val parser: CommandLineParser = new BasicParser()
    val options = new Options()
    options.addOption("ph", "policy-home", true,
        "The folder where to find the policy file given with the given policy id. "
        + "For default operation, this folder should contain the central PUMA policy (called " + CentralStaplPDP.CENTRAL_PUMA_POLICY_ID + ".stapl)")
    /*options.addOption("pid", "policy-id", true,
        "The id of the policy to be evaluated on decision requests. Default value: " + GLOBAL_PUMA_POLICY_ID + ")")
    options.addOption("s", "log-disabled", true, "Verbose mode (true/false)")*/
    var policyHome = ""
    //var policyId = ""

    // read command line
    try {
      val line = parser.parse(options, args)
      if (line.hasOption("help")) {
        val formatter = new HelpFormatter()
        formatter.printHelp("Simple PDP Test", options)
        return
      }
      if (line.hasOption("policy-home")) {
        policyHome = line.getOptionValue("policy-home")
      } else {
        warn("Incorrect arguments given.")
        return
      }
      /*if (line.hasOption("log-disabled") && Boolean.parseBoolean(line.getOptionValue("log-disabled"))) {
        info("Now switching to silent mode")
        LogManager.getLogManager().getLogger("").setLevel(Level.WARNING)
        //LogManager.getLogManager().reset()
      } 
      if (line.hasOption("policy-id")) {
        policyId = line.getOptionValue("policy-id")
      } else {
        info("Using default policy id: " + CentralStaplPDP.GLOBAL_PUMA_POLICY_ID)
        policyId = CentralStaplPDP.GLOBAL_PUMA_POLICY_ID
      }*/
    } catch {
      case e: ParseException =>
        warn("Incorrect arguments given.", e)
        return
    }
    
    
    val pdp = new CentralStaplPDP(policyHome)
    
    // SETUP RMI
    try {
      val registry = try {
        val reg = LocateRegistry.createRegistry(RMI_REGISITRY_PORT)
        info("Created new RMI registry")
        reg
      } catch {
        case e: RemoteException =>
          val reg = LocateRegistry.getRegistry(RMI_REGISITRY_PORT)
          info("Reusing existing RMI registry")
          reg
      }
      val stub = UnicastRemoteObject.exportObject(pdp, 0)//.asInstanceOf[CentralPUMAPDPMgmtRemote]
      registry.bind(CENTRAL_PUMA_PDP_RMI_NAME, stub)
      info("Central PUMA PDP up and running (available using RMI with name \"central-puma-pdp\" on RMI registry port " + RMI_REGISITRY_PORT + ")")
      Thread.sleep(100)
    } catch {
      case e: Exception =>
        error("FAILED to set up PDP as RMI server", e)
    }
    
    // SETUP THRIFT
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
