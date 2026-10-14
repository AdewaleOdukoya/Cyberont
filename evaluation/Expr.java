import org.semanticweb.owlapi.apibinding.OWLManager;
import org.semanticweb.owlapi.model.*;
import org.semanticweb.owlapi.util.*;
import java.io.File; import java.util.*;
public class Expr { public static void main(String[] a) throws Exception {
 OWLOntologyManager m=OWLManager.createOWLOntologyManager(); OWLOntology o=m.loadOntologyFromOntologyDocument(new File(a[0]));
 DLExpressivityChecker c=new DLExpressivityChecker(Collections.singleton(o));
 System.out.println(c.getConstructs()); 
 try { System.out.println(c.getClass().getMethod("expressibleInLanguages").invoke(c)); } catch(Exception e){System.out.println("no languages: "+e);} }}
