package puma.stapl.pip

import stapl.core.pdp.AttributeFinderModule
import stapl.core._
import stapl.core.pdp.EvaluationCtx
import puma.piputils.EntityDatabase
import org.joda.time.LocalDateTime
import scala.collection.JavaConversions.asScalaSet

class SubjectAttributeFinderModule extends AttributeFinderModule {
  
  private val db = EntityDatabase.getInstance()
  db.open(true)
  
  override def find(ctx: EvaluationCtx, cType: AttributeContainerType, 
      name: String, aType: AttributeType, multiValued: Boolean): Option[ConcreteValue] = {
    import scala.collection.JavaConversions._
    if(cType == SUBJECT) {
      val identifier = s"subject:${name}"
      if(multiValued)
        aType match {
          case String => Some(db.getStringAttribute(ctx.subjectId, identifier).toSeq)
          case Bool => Some(db.getBooleanAttribute(ctx.subjectId, identifier).toSeq.asInstanceOf[Seq[Boolean]])
          case Number => Some(db.getIntegerAttribute(ctx.subjectId, identifier).toSeq.asInstanceOf[Seq[Int]])
          case DateTime => Some(db.getDateAttribute(ctx.subjectId, identifier).map(date => new LocalDateTime(date)).toSeq)
          case _ => None
        }
      else
        aType match {
          case String => Some(db.getStringAttribute(ctx.subjectId, identifier).head)
          case Bool => Some(db.getBooleanAttribute(ctx.subjectId, identifier).head.asInstanceOf[Boolean])
          case Number => Some(db.getIntegerAttribute(ctx.subjectId, identifier).head.asInstanceOf[Int])
          case DateTime => Some(new LocalDateTime(db.getDateAttribute(ctx.subjectId, identifier).head))
          case _ => None
        }
    } else None
  }

}