package org.globex.retail.kubernetes;

import io.quarkus.runtime.QuarkusApplication;
import io.quarkus.runtime.annotations.QuarkusMain;

import javax.inject.Inject;

@QuarkusMain
public class RunJob implements QuarkusApplication {

    @Inject
    KubernetesRunner runner;

    @Override
    public int run(String... args) throws Exception {
        return runner.run();
    }
}
