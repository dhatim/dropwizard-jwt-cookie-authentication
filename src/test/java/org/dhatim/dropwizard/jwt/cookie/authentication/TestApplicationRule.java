/**
 * Copyright 2020 Dhatim
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.dhatim.dropwizard.jwt.cookie.authentication;

import com.codahale.metrics.health.HealthCheck;
import io.dropwizard.Application;
import io.dropwizard.Configuration;
import io.dropwizard.jetty.HttpConnectorFactory;
import io.dropwizard.logging.DefaultLoggingFactory;
import io.dropwizard.server.SimpleServerFactory;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import io.dropwizard.testing.DropwizardTestSupport;
import org.junit.rules.ExternalResource;

import java.net.URI;

/**
 * Inspired by DropwizardClientRule (which sadly cannot register bundles)
 */
public class TestApplicationRule extends ExternalResource {

    private final DropwizardTestSupport<Configuration> testSupport;

    public TestApplicationRule(){
        Configuration configuration = new Configuration();
        ((DefaultLoggingFactory)configuration.getLoggingFactory()).setLevel("DEBUG");
        this.testSupport = new DropwizardTestSupport<Configuration>(FakeApplication.class, configuration) {
            @Override
            public Application<Configuration> newApplication() {
                return new FakeApplication();
            }
        };
    }

    public URI baseUri() {
        return URI.create("http://localhost:" + testSupport.getLocalPort() + "/application");
    }

    public DropwizardTestSupport<Configuration> getSupport(){
        return testSupport;
    }

    @Override
    protected void before() throws Throwable {
        testSupport.before();
    }

    @Override
    protected void after() {
        testSupport.after();
    }

    private class FakeApplication extends Application<Configuration> {

        @Override
        public void initialize(Bootstrap<Configuration> bootstrap) {
            bootstrap.addBundle(JwtCookieAuthBundle.getDefault());
        }

        @Override
        public void run(Configuration configuration, Environment environment) {
            //choose a random port
            SimpleServerFactory serverConfig = new SimpleServerFactory();
            configuration.setServerFactory(serverConfig);
            HttpConnectorFactory connectorConfig = (HttpConnectorFactory) serverConfig.getConnector();
            connectorConfig.setPort(0);

            //Dummy health check to suppress the startup warning.
            environment.healthChecks().register("dummy", new HealthCheck() {
                @Override
                protected HealthCheck.Result check() {
                    return HealthCheck.Result.healthy();
                }
            });

            environment.jersey().register(new TestResource());
        }

    }
}
