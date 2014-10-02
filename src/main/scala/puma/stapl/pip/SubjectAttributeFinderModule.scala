package puma.stapl.pip

import stapl.core.pdp.AttributeFinderModule
import stapl.core._
import stapl.core.pdp.EvaluationCtx
import puma.piputils.EntityDatabase
import org.joda.time.LocalDateTime
import scala.collection.JavaConversions.asScalaSet

class SubjectAttributeFinderModule extends AttributeFinderModule {
  
  val db = EntityDatabase.getInstance()
  db.open(true)
  
  override def find(ctx: EvaluationCtx, cType: AttributeContainerType, 
      name: String, aType: AttributeType, multiValued: Boolean): Option[ConcreteValue] = {
    import scala.collection.JavaConversions._
    if(cType == SUBJECT)
      if(multiValued)
        aType match {
          case String => Some(db.getStringAttribute(ctx.subjectId, name).toSeq)
          case Bool => Some(db.getBooleanAttribute(ctx.subjectId, name).toSeq.asInstanceOf[Seq[Boolean]])
          case Number => Some(db.getIntegerAttribute(ctx.subjectId, name).toSeq.asInstanceOf[Seq[Int]])
          case DateTime => Some(db.getDateAttribute(ctx.subjectId, name).map(date => new LocalDateTime(date)).toSeq)
          case _ => None
        }
      else
        aType match {
          case String => Some(db.getStringAttribute(ctx.subjectId, name).head)
          case Bool => Some(db.getBooleanAttribute(ctx.subjectId, name).head.asInstanceOf[Boolean])
          case Number => Some(db.getIntegerAttribute(ctx.subjectId, name).head.asInstanceOf[Int])
          case DateTime => Some(new LocalDateTime(db.getDateAttribute(ctx.subjectId, name).head))
          case _ => None
        }
    else None
  }

}