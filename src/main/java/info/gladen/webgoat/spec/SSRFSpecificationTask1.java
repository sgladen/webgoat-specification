package info.gladen.webgoat.spec;

import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.CWE;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

@FluentTQLSpecificationClass
public class SSRFSpecificationTask1 implements FluentTQLUserInterface {
    public Method srcMethod = new MethodConfigurator(
            "org.owasp.webgoat.lessons.ssrf.SSRFTask1: " +
                    "org.owasp.webgoat.container.assignments.AttackResult completed(" +
                    "java.lang.String)")
            .out().param(0)
            .configure();

    // Note: This is not an actual sink, however, this is how this task implements the fake SSRF vulnerability.
    public Method sinkMethod = new MethodConfigurator(
            "java.lang.String: " +
                    "boolean matches(" +
                    "java.lang.String)")
            .in().thisObject()
            .configure();

    @Override
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("SSRFTask1")
                .from(srcMethod)
                .to(sinkMethod)
                .report("Found a SSRF vulnerability", CWE.CWE20) // CWE918 for SSRF, but not implemented, yet.
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<>();
        myFluentTQLSpecs.add(myTF);

        return myFluentTQLSpecs;
    }
}
