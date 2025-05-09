package info.gladen.webgoat.spec;

import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.*;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

@FluentTQLSpecificationClass
public class SSRFSpecificationTask2 implements FluentTQLUserInterface {
    public Method srcMethod = new MethodConfigurator(
            "org.owasp.webgoat.lessons.ssrf.SSRFTask2: " +
                    "org.owasp.webgoat.container.assignments.AttackResult completed(" +
                    "java.lang.String)")
            .out().param(0)
            .configure();

    public Method propagatorMethod = new MethodConfigurator(
            "java.net.URL: " +
                    "void <init>(" +
                    "java.lang.String)")
            .in().param(0)
            .out().thisObject()
            .configure();

    public Method sinkMethod = new MethodConfigurator(
            "java.net.URL: " +
                    "java.io.InputStream openStream()")
            .in().thisObject()
            .configure();

    @Override
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("SSRFTask2")
                .from(srcMethod)
                .through(propagatorMethod)
                .to(sinkMethod)
                .report("Found a SSRF vulnerability", CWE.CWE20) // CWE918 for SSRF, but not implemented, yet.
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<>();
        myFluentTQLSpecs.add(myTF);

        return myFluentTQLSpecs;
    }
}
