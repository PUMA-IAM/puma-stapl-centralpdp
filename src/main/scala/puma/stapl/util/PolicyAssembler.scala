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

object PolicyAssembler {

  private val XacmlId = """(?:subject:|resource:|action:|environment:)?(.+)""".r
  
  final val ATTRIBUTE_DEFINITIONS_FILE = "global.stapl"
  private val db = EntityDatabase.getInstance()
  db.open(true)
  
  def getGlobalPolicy(policyDir: String, identifiers: Seq[String]): Either[AbstractPolicy, Exception] = try {
    val globalAttributes = AttributesParser.parse(FileUtils.readFileToString(new File(ATTRIBUTE_DEFINITIONS_FILE)))
    
    val centralPolicy = CompleteParser.parse(
        FileUtils.readFileToString(new File(CentralStaplPDP.CENTRAL_PUMA_POLICY_ID + ".stapl")),
        globalAttributes) // XXX does the central policy specify new attributes?
    
    val tenantPolicies = for(id <- identifiers) yield getTenantPolicy(id, globalAttributes)
    
    val globalPolicy = Policy(CentralStaplPDP.CENTRAL_PUMA_POLICY_ID) := apply DenyOverrides to (
        centralPolicy +: tenantPolicies: _*
    )
    
    Left(globalPolicy)
  } catch {
    //case e: IOException => Right(e)    XXX is this correct?
    case e: Exception => Right(e)
  }
  
  private def getTenantPolicy(id: String, globalAttributes: Seq[Attribute]): AbstractPolicy = {
    import scala.collection.JavaConverters._
    val attributes: Seq[Attribute] = 
      for(family <- db.getAttributeFamiliesOfTenant(id).asScala) yield {
        val typ = family.dataType match {
          case DataType.Boolean => Bool
          case DataType.DateTime => DateTime
          case DataType.Integer => Number
          case DataType.String => String
        }
        val XacmlId(name) = family.xacmlName//.split(":").tail.mkString(":")
        
        family.multiplicity match {
          case Multiplicity.ATOMIC => SimpleAttribute(SUBJECT, name, typ)
          case Multiplicity.GROUPED => ListAttribute(SUBJECT, name, typ)
        }
      }
    
    PolicyParser.parse(FileUtils.readFileToString(new File(id + ".stapl")), globalAttributes ++ attributes)
  }

}