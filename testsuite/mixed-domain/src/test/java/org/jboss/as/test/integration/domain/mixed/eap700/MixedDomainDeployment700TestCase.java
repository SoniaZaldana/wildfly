/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015, Red Hat Middleware LLC, and individual contributors
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

package org.jboss.as.test.integration.domain.mixed.eap700;

import org.jboss.as.test.integration.domain.mixed.MixedDomainDeploymentTest;
import org.jboss.as.test.integration.domain.mixed.Version;
import org.jboss.as.test.integration.domain.mixed.Version.AsVersion;
import org.jboss.as.test.shared.TestSuiteEnvironment;
import org.junit.Assume;
import org.junit.BeforeClass;

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
@Version(AsVersion.EAP_7_0_0)
public class MixedDomainDeployment700TestCase extends MixedDomainDeploymentTest {
    @BeforeClass
    public static void beforeClass() {
        // WFLY-12649 -- embedded broker doesn't start correctly on an EAP 7.0.0 server running on OpenJ9
        Assume.assumeFalse(TestSuiteEnvironment.isJ9Jvm());
        // WFLY-14022 -- 7.0.0.GA under certain JDK and Linux kernel versions expose ARTEMIS-2800
        final String value = System.getProperty("ignore.ARTEMIS-2800");
        Assume.assumeFalse(value != null && (value.isEmpty() || Boolean.parseBoolean(value)));

        MixedDomain700TestSuite.initializeDomain();
    }

    @Override
    protected boolean supportManagedExplodedDeployment() {
        return false;
    }
}
