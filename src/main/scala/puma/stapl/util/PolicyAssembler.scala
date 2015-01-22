package puma.stapl.util

import stapl.core.AbstractPolicy
import java.io.IOException
import org.apache.commons.io.FileUtils
import java.io.File
import puma.stapl.centralpdp.CentralStaplPDP
import puma.piputils.EntityDatabase
import puma.piputils.Multiplicity
import puma.piputils.DataType
import stapl.core.Attribute
import stapl.parser.PolicyParser
import scala.util.Success
import scala.util.Failure
import org.parboiled2.ParseError
import stapl.core._
import stapl.parser.AttributesParser
import stapl.parser.CompleteParser
import scala.util.Try

object PolicyAssembler {

  private val XacmlId = """(?:subject:|resource:|action:|environment:)?(.+)""".r
  
  final val GLOBAL_ATTRIBUTE_DEFINITIONS_FILE = "global.stapl"
  private val db = EntityDatabase.getInstance()
  db.open(true)
  
  def getGlobalPolicy(policyDir: String, identifiers: Seq[String]): Try[AbstractPolicy] = 
    Try {
      import stapl.parser.AttributesParser.Strategies.NameToAttribute
      val globalAttributes = AttributesParser.parse(FileUtils.readFileToString(new File(policyDir + GLOBAL_ATTRIBUTE_DEFINITIONS_FILE)))
    
      val centralPolicy = CompleteParser.parse(
          FileUtils.readFileToString(new File(policyDir + CentralStaplPDP.CENTRAL_PUMA_POLICY_ID + ".stapl")),
          globalAttributes) // XXX does the central policy specify new attributes?
      
      val tenantPolicies = for(id <- identifiers) yield getTenantPolicy(policyDir, id, globalAttributes)
      
      val globalPolicy = Policy(CentralStaplPDP.CENTRAL_PUMA_POLICY_ID) := apply DenyOverrides to (
          centralPolicy +: tenantPolicies: _*
      )
      
      globalPolicy
  }
  
  private def getTenantPolicy(policyDir: String, id: String, globalAttributes: Map[String, Attribute]): AbstractPolicy = {
    import scala.collection.JavaConverters._
    val attributes: Map[String, Attribute] = 
      (for(family <- db.getAttributeFamiliesOfTenant(id).asScala) yield {
        val typ = family.dataType match {
          case DataType.Boolean => Bool
          case DataType.DateTime => DateTime
          case DataType.Integer => Number
          case DataType.String => String
        }
        val XacmlId(name) = family.xacmlName//.split(":").tail.mkString(":")
        
        family.multiplicity match {
          case Multiplicity.ATOMIC => name -> SimpleAttribute(SUBJECT, name, typ)
          case Multiplicity.GROUPED => name -> ListAttribute(SUBJECT, name, typ)
        }
      }).toMap
    
    PolicyParser.parse(FileUtils.readFileToString(new File(policyDir + id + ".stapl")), globalAttributes ++ attributes)
  }

}