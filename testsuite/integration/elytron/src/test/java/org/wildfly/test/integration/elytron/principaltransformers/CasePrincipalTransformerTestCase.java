/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.wildfly.test.integration.elytron.principaltransformers;

import static javax.servlet.http.HttpServletResponse.SC_OK;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

import java.net.MalformedURLException;
import java.net.URL;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.test.integration.management.util.CLIWrapper;
import org.jboss.as.test.integration.security.common.Utils;
import org.jboss.as.test.integration.security.common.servlets.SimpleSecuredServlet;
import org.jboss.as.test.integration.security.common.servlets.SimpleServlet;
import org.jboss.as.test.shared.ServerReload;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.test.security.common.elytron.PropertyFileBasedDomain;


/**
 * Test case for 'case-principal-transformer' Elytron subsystem resource.
 *
 * @author Sonia Zaldana Calles <szaldana@redhat.com>
 */
@RunWith(Arquillian.class)
@RunAsClient
@ServerSetup({CasePrincipalTransformerTestCase.SetupTask.class})
public class CasePrincipalTransformerTestCase {

    private static final String DEP_SECURITY_DOMAIN = "case-principal-domain";
    private static final String USER = "USER1";
    private static final String PASSWORD = "password1";
    private static final String ROLE = "JBossAdmin";

    @Deployment(name = DEP_SECURITY_DOMAIN)
    public static WebArchive createDeployment() {
        final WebArchive war = ShrinkWrap.create(WebArchive.class, DEP_SECURITY_DOMAIN + ".war");
        war.addClasses(SimpleServlet.class);
        war.addClasses(SimpleSecuredServlet.class);
        war.addAsWebInfResource(ConstantPrincipalTransformerTestCase.class.getPackage(), "principal-transformer-web.xml", "web.xml");
        war.addAsWebInfResource(Utils.getJBossWebXmlAsset(DEP_SECURITY_DOMAIN), "jboss-web.xml");
        return war;
    }

    /**
     * Test whether name of user passed to security domain is adjusted into upper case with
     * the 'case-principal-transformer'. Test also checks that authentication passes for correct password.
     */
    @Test
    @OperateOnDeployment(DEP_SECURITY_DOMAIN)
    public void testPassingUserAndCorrectPassword(@ArquillianResource URL webAppURL) throws Exception {
        URL url = prepareUrl(webAppURL);
        Utils.makeCallWithBasicAuthn(url, "user1", PASSWORD, SC_OK);
    }

    /**
     * Test checks that authentication fails for incorrect password if 'case-principal-transformer' is used.
     */
    @Test
    @OperateOnDeployment(DEP_SECURITY_DOMAIN)
    public void testPassingUserAndWrongPassword(@ArquillianResource URL webAppURL) throws Exception {
        URL url = prepareUrl(webAppURL);
        Utils.makeCallWithBasicAuthn(url, USER, "wrongPassword", SC_UNAUTHORIZED);
    }

    /**
     * Test checks that authentication fails for incorrect password and incorrect user if 'case-principal-transformer'
     * is used.
     */
    @Test
    @OperateOnDeployment(DEP_SECURITY_DOMAIN)
    public void testPassingWrongUserAndWrongPassword(@ArquillianResource URL webAppURL) throws Exception {
        URL url = prepareUrl(webAppURL);
        Utils.makeCallWithBasicAuthn(url, "wrongUser", "wrongPassword", SC_UNAUTHORIZED);
    }

    private URL prepareUrl(URL url) throws MalformedURLException {
        return new URL(url.toExternalForm() + SimpleSecuredServlet.SERVLET_PATH.substring(1));
    }

    static class SetupTask implements ServerSetupTask {

        private static final String ELYTRON_SECURITY = "elytronDomain";
        private static final String PRINCIPAL_TRANSFORMER = "transformer";
        private static final String PREDEFINED_HTTP_SERVER_MECHANISM_FACTORY = "global";

        PropertyFileBasedDomain domain;


        @Override
        public void setup(ManagementClient managementClient, String containerId) throws Exception {
            try (CLIWrapper cli = new CLIWrapper(true)) {
                domain = PropertyFileBasedDomain.builder().withName(ELYTRON_SECURITY)
                        .withUser(USER, PASSWORD, ROLE)
                        .build();
                domain.create(cli);
                cli.sendLine(String.format(
                        "/subsystem=elytron/case-principal-transformer=%s:add(upper-case=%s)",
                        PRINCIPAL_TRANSFORMER, true));
                cli.sendLine(String.format(
                        "/subsystem=elytron/security-domain=%s:write-attribute(name=realms[0].principal-transformer,value=%s)",
                        ELYTRON_SECURITY, PRINCIPAL_TRANSFORMER));
                cli.sendLine(String.format(
                        "/subsystem=elytron/http-authentication-factory=%1$s:add(http-server-mechanism-factory=%2$s,security-domain=%1$s,"
                                + "mechanism-configurations=[{mechanism-name=BASIC,mechanism-realm-configurations=[{realm-name=\"%1$s\"}]}])",
                        ELYTRON_SECURITY, PREDEFINED_HTTP_SERVER_MECHANISM_FACTORY));
                cli.sendLine(String.format(
                        "/subsystem=undertow/application-security-domain=%s:add(http-authentication-factory=%s)",
                        DEP_SECURITY_DOMAIN, ELYTRON_SECURITY));
            }
            ServerReload.reloadIfRequired(managementClient);
        }

        @Override
        public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
            try (CLIWrapper cli = new CLIWrapper(true)) {
                cli.sendLine(String.format(
                        "/subsystem=elytron/security-domain=%s:undefine-attribute(name=realms[0].principal-transformer)",
                        ELYTRON_SECURITY));
                cli.sendLine(String.format("/subsystem=undertow/application-security-domain=%s:remove()", DEP_SECURITY_DOMAIN));
                cli.sendLine(String.format("/subsystem=elytron/http-authentication-factory=%s:remove()", ELYTRON_SECURITY));
                cli.sendLine(String.format("/subsystem=elytron/case-principal-transformer=%s:remove()", PRINCIPAL_TRANSFORMER));
                domain.remove(cli);
            }
            ServerReload.reloadIfRequired(managementClient);
        }
    }
}
