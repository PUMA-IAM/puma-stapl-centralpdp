package puma.stapl.centralpdp

import org.scalatest.FunSuite
import org.scalatest.BeforeAndAfterAll
import puma.thrift.pdp.RemotePDPService
import org.apache.thrift.transport.TServerTransport
import org.apache.thrift.transport.TServerSocket
import org.apache.thrift.server.TServer
import org.apache.thrift.server.TSimpleServer
import puma.stapl.pdp.CentralPolicyRemoteEvaluatorModule
import stapl.core.pdp.PDP
import stapl.core.pdp.RemoteEvaluator
import stapl.core.BasicPolicy
import org.joda.time.LocalDateTime
import puma.stapl.pdp.StaplPDP
import puma.peputils.Subject
import puma.peputils.Object
import puma.peputils.Action
import puma.peputils.Environment
import puma.peputils.attributes.SubjectAttributeValue
import puma.peputils.attributes.Multiplicity
import puma.peputils.PDPDecision
import puma.peputils.attributes.ObjectAttributeValue
import puma.peputils.attributes.ActionAttributeValue
import puma.peputils.attributes.EnvironmentAttributeValue

/**
 * Test the combined functionality of the CentralStaplPDP, StaplPDP and CentralPolicyRemoteEvaluatorModule.
 */
class ThriftServerTest extends FunSuite with BeforeAndAfterAll {
  
  var appPDP: StaplPDP = null
  var pdpServer: TServer = null
  val now = new LocalDateTime()
  
  override def beforeAll {
    val centralpdp = new CentralStaplPDP with BasicPolicy {
      import stapl.core._
      subject.string = SimpleAttribute(String)
      subject.strings = ListAttribute(String)
      resource.int = SimpleAttribute(Number)
      resource.ints = ListAttribute(Number)
      action.double = SimpleAttribute(Number)
      action.doubles = ListAttribute(Number)
      environment.boolean = SimpleAttribute(Bool)
      environment.booleans = ListAttribute(Bool)
      environment.datetime = SimpleAttribute(DateTime)
      environment.datetimes = ListAttribute(DateTime)
      
      override val pdp = new PDP(
        Policy("policy") := apply FirstApplicable to (
          Rule("string") := permit iff ("student" === subject.string),
          Rule("strings") := permit iff ("student" in subject.strings),
          Rule("int") := permit iff (5 === resource.int),
          Rule("ints") := permit iff (5 in resource.ints),
          Rule("double") := permit iff (5.7 === action.double),
          Rule("doubles") := permit iff (5.7 in action.doubles),
          Rule("boolean") := permit iff (environment.boolean),
          Rule("booleans") := permit iff (true in environment.booleans),
          Rule("datetime") := permit iff (now === environment.datetime),
          Rule("datetimes") := permit iff (now in environment.datetimes),
          Rule("default") := deny
        )
      )
    }
    val port = 9091
    
    val pdpProcessor: RemotePDPService.Processor[CentralStaplPDP] = new RemotePDPService.Processor[CentralStaplPDP](centralpdp)
    val pdpServerTransport: TServerTransport = new TServerSocket(port)
    pdpServer = new TSimpleServer(new TServer.Args(pdpServerTransport).processor(pdpProcessor))
    //info("Setting up the test server on port " + port)
    
    new Thread(new Runnable() {     
      @Override
      override def run() {
        pdpServer.serve()
      }
    }, "CentralPDP-Server-Thread").start()
    
    // wait until the server should be running
    Thread.sleep(100)
    
    appPDP = new StaplPDP {
      override val pdp = 
        new PDP({
          import stapl.core._
          Policy("application-policy") := apply DenyOverrides to (
            RemotePolicy("central-puma-policy")
          )
        },
        {
          val evaluator = new RemoteEvaluator
          evaluator += new CentralPolicyRemoteEvaluatorModule
          evaluator
        })
    }
  }
  
  override def afterAll {
    pdpServer.stop()
  }
  
  
  test("atomic STRING attribute") {
    val subject = new Subject("subjectID")
    val resource = new Object("objectID")
    val action = new Action("actionID")
    val env = new Environment()
    
    subject.addAttributeValue(new SubjectAttributeValue("string", Multiplicity.ATOMIC, "student"))
    subject.addAttributeValue(new SubjectAttributeValue("strings", Multiplicity.GROUPED, "bla"))
    resource.addAttributeValue(new ObjectAttributeValue("int", Multiplicity.ATOMIC, 0))
    resource.addAttributeValue(new ObjectAttributeValue("ints", Multiplicity.GROUPED, 0))
    action.addAttributeValue{val v = new ActionAttributeValue("double", Multiplicity.ATOMIC); v.addValue(0.0); v}
    action.addAttributeValue{val v = new ActionAttributeValue("doubles", Multiplicity.GROUPED); v.addValue(0.0); v}
    env.addAttributeValue(new EnvironmentAttributeValue("boolean", Multiplicity.ATOMIC, false))
    env.addAttributeValue(new EnvironmentAttributeValue("booleans", Multiplicity.GROUPED, false))
    env.addAttributeValue(new EnvironmentAttributeValue("datetime", Multiplicity.ATOMIC, now.minusYears(3).toDate()))
    env.addAttributeValue(new EnvironmentAttributeValue("datetimes", Multiplicity.GROUPED, now.minusYears(3).toDate()))
    
    val decision = appPDP.evaluate(subject, resource, action, env).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("grouped STRING attribute") {
    val subject = new Subject("subjectID")
    val resource = new Object("objectID")
    val action = new Action("actionID")
    val env = new Environment()
    
    subject.addAttributeValue(new SubjectAttributeValue("string", Multiplicity.ATOMIC, "bla"))
    subject.addAttributeValue(new SubjectAttributeValue("strings", Multiplicity.GROUPED, "student"))
    resource.addAttributeValue(new ObjectAttributeValue("int", Multiplicity.ATOMIC, 0))
    resource.addAttributeValue(new ObjectAttributeValue("ints", Multiplicity.GROUPED, 0))
    action.addAttributeValue{val v = new ActionAttributeValue("double", Multiplicity.ATOMIC); v.addValue(0.0); v}
    action.addAttributeValue{val v = new ActionAttributeValue("doubles", Multiplicity.GROUPED); v.addValue(0.0); v}
    env.addAttributeValue(new EnvironmentAttributeValue("boolean", Multiplicity.ATOMIC, false))
    env.addAttributeValue(new EnvironmentAttributeValue("booleans", Multiplicity.GROUPED, false))
    env.addAttributeValue(new EnvironmentAttributeValue("datetime", Multiplicity.ATOMIC, now.minusYears(3).toDate()))
    env.addAttributeValue(new EnvironmentAttributeValue("datetimes", Multiplicity.GROUPED, now.minusYears(3).toDate()))
    
    val decision = appPDP.evaluate(subject, resource, action, env).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("atomic INT attribute") {
    val subject = new Subject("subjectID")
    val resource = new Object("objectID")
    val action = new Action("actionID")
    val env = new Environment()
    
    subject.addAttributeValue(new SubjectAttributeValue("string", Multiplicity.ATOMIC, "bla"))
    subject.addAttributeValue(new SubjectAttributeValue("strings", Multiplicity.GROUPED, "bla"))
    resource.addAttributeValue(new ObjectAttributeValue("int", Multiplicity.ATOMIC, 5))
    resource.addAttributeValue(new ObjectAttributeValue("ints", Multiplicity.GROUPED, 0))
    action.addAttributeValue{val v = new ActionAttributeValue("double", Multiplicity.ATOMIC); v.addValue(0.0); v}
    action.addAttributeValue{val v = new ActionAttributeValue("doubles", Multiplicity.GROUPED); v.addValue(0.0); v}
    env.addAttributeValue(new EnvironmentAttributeValue("boolean", Multiplicity.ATOMIC, false))
    env.addAttributeValue(new EnvironmentAttributeValue("booleans", Multiplicity.GROUPED, false))
    env.addAttributeValue(new EnvironmentAttributeValue("datetime", Multiplicity.ATOMIC, now.minusYears(3).toDate()))
    env.addAttributeValue(new EnvironmentAttributeValue("datetimes", Multiplicity.GROUPED, now.minusYears(3).toDate()))
    
    val decision = appPDP.evaluate(subject, resource, action, env).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("grouped INT attribute") {
    val subject = new Subject("subjectID")
    val resource = new Object("objectID")
    val action = new Action("actionID")
    val env = new Environment()
    
    subject.addAttributeValue(new SubjectAttributeValue("string", Multiplicity.ATOMIC, "bla"))
    subject.addAttributeValue(new SubjectAttributeValue("strings", Multiplicity.GROUPED, "bla"))
    resource.addAttributeValue(new ObjectAttributeValue("int", Multiplicity.ATOMIC, 0))
    resource.addAttributeValue(new ObjectAttributeValue("ints", Multiplicity.GROUPED, 5))
    action.addAttributeValue{val v = new ActionAttributeValue("double", Multiplicity.ATOMIC); v.addValue(0.0); v}
    action.addAttributeValue{val v = new ActionAttributeValue("doubles", Multiplicity.GROUPED); v.addValue(0.0); v}
    env.addAttributeValue(new EnvironmentAttributeValue("boolean", Multiplicity.ATOMIC, false))
    env.addAttributeValue(new EnvironmentAttributeValue("booleans", Multiplicity.GROUPED, false))
    env.addAttributeValue(new EnvironmentAttributeValue("datetime", Multiplicity.ATOMIC, now.minusYears(3).toDate()))
    env.addAttributeValue(new EnvironmentAttributeValue("datetimes", Multiplicity.GROUPED, now.minusYears(3).toDate()))
    
    val decision = appPDP.evaluate(subject, resource, action, env).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("atomic DOUBLE attribute") {
    val subject = new Subject("subjectID")
    val resource = new Object("objectID")
    val action = new Action("actionID")
    val env = new Environment()
    
    subject.addAttributeValue(new SubjectAttributeValue("string", Multiplicity.ATOMIC, "bla"))
    subject.addAttributeValue(new SubjectAttributeValue("strings", Multiplicity.GROUPED, "bla"))
    resource.addAttributeValue(new ObjectAttributeValue("int", Multiplicity.ATOMIC, 0))
    resource.addAttributeValue(new ObjectAttributeValue("ints", Multiplicity.GROUPED, 0))
    action.addAttributeValue{val v = new ActionAttributeValue("double", Multiplicity.ATOMIC); v.addValue(5.7); v}
    action.addAttributeValue{val v = new ActionAttributeValue("doubles", Multiplicity.GROUPED); v.addValue(0.0); v}
    env.addAttributeValue(new EnvironmentAttributeValue("boolean", Multiplicity.ATOMIC, false))
    env.addAttributeValue(new EnvironmentAttributeValue("booleans", Multiplicity.GROUPED, false))
    env.addAttributeValue(new EnvironmentAttributeValue("datetime", Multiplicity.ATOMIC, now.minusYears(3).toDate()))
    env.addAttributeValue(new EnvironmentAttributeValue("datetimes", Multiplicity.GROUPED, now.minusYears(3).toDate()))
    
    val decision = appPDP.evaluate(subject, resource, action, env).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("grouped DOUBLE attribute") {
    val subject = new Subject("subjectID")
    val resource = new Object("objectID")
    val action = new Action("actionID")
    val env = new Environment()
    
    subject.addAttributeValue(new SubjectAttributeValue("string", Multiplicity.ATOMIC, "bla"))
    subject.addAttributeValue(new SubjectAttributeValue("strings", Multiplicity.GROUPED, "bla"))
    resource.addAttributeValue(new ObjectAttributeValue("int", Multiplicity.ATOMIC, 0))
    resource.addAttributeValue(new ObjectAttributeValue("ints", Multiplicity.GROUPED, 0))
    action.addAttributeValue{val v = new ActionAttributeValue("double", Multiplicity.ATOMIC); v.addValue(0.0); v}
    action.addAttributeValue{val v = new ActionAttributeValue("doubles", Multiplicity.GROUPED); v.addValue(5.7); v}
    env.addAttributeValue(new EnvironmentAttributeValue("boolean", Multiplicity.ATOMIC, false))
    env.addAttributeValue(new EnvironmentAttributeValue("booleans", Multiplicity.GROUPED, false))
    env.addAttributeValue(new EnvironmentAttributeValue("datetime", Multiplicity.ATOMIC, now.minusYears(3).toDate()))
    env.addAttributeValue(new EnvironmentAttributeValue("datetimes", Multiplicity.GROUPED, now.minusYears(3).toDate()))
    
    val decision = appPDP.evaluate(subject, resource, action, env).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("atomic BOOLEAN attribute") {
    val subject = new Subject("subjectID")
    val resource = new Object("objectID")
    val action = new Action("actionID")
    val env = new Environment()
    
    subject.addAttributeValue(new SubjectAttributeValue("string", Multiplicity.ATOMIC, "bla"))
    subject.addAttributeValue(new SubjectAttributeValue("strings", Multiplicity.GROUPED, "bla"))
    resource.addAttributeValue(new ObjectAttributeValue("int", Multiplicity.ATOMIC, 0))
    resource.addAttributeValue(new ObjectAttributeValue("ints", Multiplicity.GROUPED, 0))
    action.addAttributeValue{val v = new ActionAttributeValue("double", Multiplicity.ATOMIC); v.addValue(0.0); v}
    action.addAttributeValue{val v = new ActionAttributeValue("doubles", Multiplicity.GROUPED); v.addValue(0.0); v}
    env.addAttributeValue(new EnvironmentAttributeValue("boolean", Multiplicity.ATOMIC, true))
    env.addAttributeValue(new EnvironmentAttributeValue("booleans", Multiplicity.GROUPED, false))
    env.addAttributeValue(new EnvironmentAttributeValue("datetime", Multiplicity.ATOMIC, now.minusYears(3).toDate()))
    env.addAttributeValue(new EnvironmentAttributeValue("datetimes", Multiplicity.GROUPED, now.minusYears(3).toDate()))
    
    val decision = appPDP.evaluate(subject, resource, action, env).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("grouped BOOLEAN attribute") {
    val subject = new Subject("subjectID")
    val resource = new Object("objectID")
    val action = new Action("actionID")
    val env = new Environment()
    
    subject.addAttributeValue(new SubjectAttributeValue("string", Multiplicity.ATOMIC, "bla"))
    subject.addAttributeValue(new SubjectAttributeValue("strings", Multiplicity.GROUPED, "bla"))
    resource.addAttributeValue(new ObjectAttributeValue("int", Multiplicity.ATOMIC, 0))
    resource.addAttributeValue(new ObjectAttributeValue("ints", Multiplicity.GROUPED, 0))
    action.addAttributeValue{val v = new ActionAttributeValue("double", Multiplicity.ATOMIC); v.addValue(0.0); v}
    action.addAttributeValue{val v = new ActionAttributeValue("doubles", Multiplicity.GROUPED); v.addValue(0.0); v}
    env.addAttributeValue(new EnvironmentAttributeValue("boolean", Multiplicity.ATOMIC, false))
    env.addAttributeValue(new EnvironmentAttributeValue("booleans", Multiplicity.GROUPED, true))
    env.addAttributeValue(new EnvironmentAttributeValue("datetime", Multiplicity.ATOMIC, now.minusYears(3).toDate()))
    env.addAttributeValue(new EnvironmentAttributeValue("datetimes", Multiplicity.GROUPED, now.minusYears(3).toDate()))
    
    val decision = appPDP.evaluate(subject, resource, action, env).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("atomic DATETIME attribute") {
    val subject = new Subject("subjectID")
    val resource = new Object("objectID")
    val action = new Action("actionID")
    val env = new Environment()
    
    subject.addAttributeValue(new SubjectAttributeValue("string", Multiplicity.ATOMIC, "bla"))
    subject.addAttributeValue(new SubjectAttributeValue("strings", Multiplicity.GROUPED, "bla"))
    resource.addAttributeValue(new ObjectAttributeValue("int", Multiplicity.ATOMIC, 0))
    resource.addAttributeValue(new ObjectAttributeValue("ints", Multiplicity.GROUPED, 0))
    action.addAttributeValue{val v = new ActionAttributeValue("double", Multiplicity.ATOMIC); v.addValue(0.0); v}
    action.addAttributeValue{val v = new ActionAttributeValue("doubles", Multiplicity.GROUPED); v.addValue(0.0); v}
    env.addAttributeValue(new EnvironmentAttributeValue("boolean", Multiplicity.ATOMIC, false))
    env.addAttributeValue(new EnvironmentAttributeValue("booleans", Multiplicity.GROUPED, false))
    env.addAttributeValue(new EnvironmentAttributeValue("datetime", Multiplicity.ATOMIC, now.toDate()))
    env.addAttributeValue(new EnvironmentAttributeValue("datetimes", Multiplicity.GROUPED, now.minusYears(3).toDate()))
    
    val decision = appPDP.evaluate(subject, resource, action, env).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("grouped DATETIME attribute") {
    val subject = new Subject("subjectID")
    val resource = new Object("objectID")
    val action = new Action("actionID")
    val env = new Environment()
    
    subject.addAttributeValue(new SubjectAttributeValue("string", Multiplicity.ATOMIC, "bla"))
    subject.addAttributeValue(new SubjectAttributeValue("strings", Multiplicity.GROUPED, "bla"))
    resource.addAttributeValue(new ObjectAttributeValue("int", Multiplicity.ATOMIC, 0))
    resource.addAttributeValue(new ObjectAttributeValue("ints", Multiplicity.GROUPED, 0))
    action.addAttributeValue{val v = new ActionAttributeValue("double", Multiplicity.ATOMIC); v.addValue(0.0); v}
    action.addAttributeValue{val v = new ActionAttributeValue("doubles", Multiplicity.GROUPED); v.addValue(0.0); v}
    env.addAttributeValue(new EnvironmentAttributeValue("boolean", Multiplicity.ATOMIC, false))
    env.addAttributeValue(new EnvironmentAttributeValue("booleans", Multiplicity.GROUPED, false))
    env.addAttributeValue(new EnvironmentAttributeValue("datetime", Multiplicity.ATOMIC, now.minusYears(3).toDate()))
    env.addAttributeValue(new EnvironmentAttributeValue("datetimes", Multiplicity.GROUPED, now.toDate()))
    
    val decision = appPDP.evaluate(subject, resource, action, env).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("jump to default deny") {
    val subject = new Subject("subjectID")
    val resource = new Object("objectID")
    val action = new Action("actionID")
    val env = new Environment()
    
    subject.addAttributeValue(new SubjectAttributeValue("string", Multiplicity.ATOMIC, "bla"))
    subject.addAttributeValue(new SubjectAttributeValue("strings", Multiplicity.GROUPED, "bla"))
    resource.addAttributeValue(new ObjectAttributeValue("int", Multiplicity.ATOMIC, 0))
    resource.addAttributeValue(new ObjectAttributeValue("ints", Multiplicity.GROUPED, 0))
    action.addAttributeValue{val v = new ActionAttributeValue("double", Multiplicity.ATOMIC); v.addValue(0.0); v}
    action.addAttributeValue{val v = new ActionAttributeValue("doubles", Multiplicity.GROUPED); v.addValue(0.0); v}
    env.addAttributeValue(new EnvironmentAttributeValue("boolean", Multiplicity.ATOMIC, false))
    env.addAttributeValue(new EnvironmentAttributeValue("booleans", Multiplicity.GROUPED, false))
    env.addAttributeValue(new EnvironmentAttributeValue("datetime", Multiplicity.ATOMIC, now.minusYears(3).toDate()))
    env.addAttributeValue(new EnvironmentAttributeValue("datetimes", Multiplicity.GROUPED, now.minusYears(3).toDate()))
    
    val decision = appPDP.evaluate(subject, resource, action, env).getDecision()
    assert(decision === PDPDecision.DENY)
  }
  
  test("missing attribute") {
    val subject = new Subject("subjectID")
    val resource = new Object("objectID")
    val action = new Action("actionID")
    val env = new Environment()
    
    subject.addAttributeValue(new SubjectAttributeValue("string", Multiplicity.ATOMIC, "bla"))
    subject.addAttributeValue(new SubjectAttributeValue("strings", Multiplicity.GROUPED, "bla"))
    resource.addAttributeValue(new ObjectAttributeValue("int", Multiplicity.ATOMIC, 0))
    resource.addAttributeValue(new ObjectAttributeValue("ints", Multiplicity.GROUPED, 0))
    action.addAttributeValue{val v = new ActionAttributeValue("double", Multiplicity.ATOMIC); v.addValue(0.0); v}
    action.addAttributeValue{val v = new ActionAttributeValue("doubles", Multiplicity.GROUPED); v.addValue(0.0); v}
    env.addAttributeValue(new EnvironmentAttributeValue("boolean", Multiplicity.ATOMIC, false))
    //env.addAttributeValue(new EnvironmentAttributeValue("booleans", Multiplicity.GROUPED, false))
    env.addAttributeValue(new EnvironmentAttributeValue("datetime", Multiplicity.ATOMIC, now.minusYears(3).toDate()))
    env.addAttributeValue(new EnvironmentAttributeValue("datetimes", Multiplicity.GROUPED, now.minusYears(3).toDate()))
    
    val decision = appPDP.evaluate(subject, resource, action, env).getDecision()
    assert(decision === PDPDecision.INDETERMINATE)
  }
  
}