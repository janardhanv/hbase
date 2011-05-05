/**
 * Copyright 2009 The Apache Software Foundation
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.hbase.zookeeper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseTestingUtility;
import org.apache.hadoop.hbase.TestZooKeeper;
import org.apache.hadoop.hbase.zookeeper.ZKUtil;
import org.apache.hadoop.hbase.zookeeper.ZooKeeperWatcher;
import org.apache.zookeeper.ZooDefs;
import org.apache.zookeeper.data.ACL;
import org.apache.zookeeper.data.Stat;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class TestZooKeeperACL {
  private final Log LOG = LogFactory.getLog(this.getClass());

  private final static HBaseTestingUtility
      TEST_UTIL = new HBaseTestingUtility();

  /**
   * @throws java.lang.Exception
   */
  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    // Test we can first start the ZK cluster by itself

    try {
      File saslConfFile = File.createTempFile("tmp", "jaas.conf");
      FileWriter fwriter = new FileWriter(saslConfFile);

      fwriter.write("" +
                    "Server {\n" +
                          "org.apache.zookeeper.server.auth.DigestLoginModule required\n" +
                          "user_hbase=\"secret\";\n" +
                          "};\n" +
                          "Client {\n" +
                          "org.apache.zookeeper.server.auth.DigestLoginModule required\n" +
                          "username=\"hbase\"\n" +
                          "password=\"secret\";\n" +
                          "};" + "\n");
      fwriter.close();
      System.setProperty("java.security.auth.login.config",saslConfFile.getAbsolutePath());
    }
    catch (IOException e) {
      // could not create tmp directory to hold JAAS conf file : test will fail now.
    }
    System.setProperty("zookeeper.authProvider.1","org.apache.zookeeper.server.auth.SASLAuthenticationProvider");

    TEST_UTIL.startMiniZKCluster();
    TEST_UTIL.getConfiguration().setBoolean("dfs.support.append", true);
    TEST_UTIL.startMiniCluster(2);
  }

  /**
   * @throws java.lang.Exception
   */
  @AfterClass
  public static void tearDownAfterClass() throws Exception {
    TEST_UTIL.shutdownMiniCluster();
  }

  /**
   * @throws java.lang.Exception
   */
  @Before
  public void setUp() throws Exception {
    TEST_UTIL.ensureSomeRegionServersAvailable(2);
  }

  /**
   * Create a node and check its ACL. When authentication is enabled on Zookeeper, all nodes (except /hbase/root-region-server and /hbase/master) should be created with
   * ZKUtil.createX (X in {createWithParents,createEphemeralNodeAndWatch,createNodeIfNotExistsAndWatch,createAndWatch,...})
   * should be created so that only the hbase server user (master or region server user)
   * that created them can access them, and this user should have all permissions on this node.
   * For /hbase/root-region-server and /hbase/master, the permissions should be as
   * above, but should also be world-readable. The latter set is checked in the 
   * next test.
   * @throws Exception
   */
  @Test
  public void testHBaseRootZNodeACL() throws Exception {
    ZooKeeperWatcher zkw = new ZooKeeperWatcher(
      new Configuration(TEST_UTIL.getConfiguration()), 
      TestZooKeeper.class.getName(), null);
    List<ACL> acls = zkw.getZooKeeper().getACL("/hbase", new Stat());
    assertEquals(acls.size(),1);
    assertEquals(acls.get(0).getId().getScheme(),"sasl");
    assertEquals(acls.get(0).getId().getId(),"hbase");
    assertEquals(acls.get(0).getPerms(), ZooDefs.Perms.ALL);
  }

  /**
   * When authentication is enabled on Zookeeper,
   * /hbase/root-region-server should be created with 2 ACLs: one specifies that
   * the hbase user has full access to the node; the other, that it is world-readable.
   * @throws Exception
   */
  @Test
  public void testHBaseRootRegionServerZNodeACL() throws Exception {
    ZooKeeperWatcher zkw = new ZooKeeperWatcher(
      new Configuration(TEST_UTIL.getConfiguration()), 
      TestZooKeeper.class.getName(), null);
    List<ACL> acls = zkw.getZooKeeper().getACL("/hbase/root-region-server", new Stat());
    assertEquals(acls.size(),2);

    boolean foundWorldReadableAcl = false;
    boolean foundHBaseOwnerAcl = false;
    for(int i = 0; i < 2; i++) {
      if (acls.get(i).getId().getScheme().equals("world") == true) {
        assertEquals(acls.get(0).getId().getId(),"anyone");
        assertEquals(acls.get(0).getPerms(), ZooDefs.Perms.READ);
        foundWorldReadableAcl = true;
      }
      else {
        if (acls.get(i).getId().getScheme().equals("sasl") == true) {
          assertEquals(acls.get(1).getId().getId(),"hbase");
          assertEquals(acls.get(1).getId().getScheme(),"sasl");
          foundHBaseOwnerAcl = true;
        }
        else { // error: should not get here: test fails.
          assertTrue(false);
        }
      }
    }
    assertTrue(foundWorldReadableAcl);
    assertTrue(foundHBaseOwnerAcl);
  }

  /**
   * When authentication is enabled on Zookeeper,
   * /hbase/master should be created with 2 ACLs: one specifies that
   * the hbase user has full access to the node; the other, that it is world-readable.
   * @throws Exception
   */
  @Test
  public void testHBaseMasterServerZNodeACL() throws Exception {
    ZooKeeperWatcher zkw = new ZooKeeperWatcher(
      new Configuration(TEST_UTIL.getConfiguration()),
      TestZooKeeper.class.getName(), null);
    List<ACL> acls = zkw.getZooKeeper().getACL("/hbase/master", new Stat());
    assertEquals(acls.size(),2);

    boolean foundWorldReadableAcl = false;
    boolean foundHBaseOwnerAcl = false;
    for(int i = 0; i < 2; i++) {
      if (acls.get(i).getId().getScheme().equals("world") == true) {
        assertEquals(acls.get(0).getId().getId(),"anyone");
        assertEquals(acls.get(0).getPerms(), ZooDefs.Perms.READ);
        foundWorldReadableAcl = true;
      }
      else {
        if (acls.get(i).getId().getScheme().equals("sasl") == true) {
          assertEquals(acls.get(1).getId().getId(),"hbase");
          assertEquals(acls.get(1).getId().getScheme(),"sasl");
          foundHBaseOwnerAcl = true;
        }
        else { // error: should not get here: test fails.
          assertTrue(false);
        }
      }
    }
    assertTrue(foundWorldReadableAcl);
    assertTrue(foundHBaseOwnerAcl);
  }


  /**
    * Same as above tests, but create a new node ("/testACLNode") outside of the /hbase hierarchy. Should have same permssions as other nodes within the /hbase hierarchy.
    * @throws Exception
   */
  @Test
  public void testOutsideHBaseNodeACL() throws Exception {
    ZooKeeperWatcher zkw = new ZooKeeperWatcher(
      new Configuration(TEST_UTIL.getConfiguration()),
      TestZooKeeper.class.getName(), null);
    ZKUtil.createWithParents(zkw, "/testACLNode");
    List<ACL> acls = zkw.getZooKeeper().getACL("/testACLNode", new Stat());
    assertEquals(acls.size(),1);
    assertEquals(acls.get(0).getId().getScheme(),"sasl");
    assertEquals(acls.get(0).getId().getId(),"hbase");
    assertEquals(acls.get(0).getPerms(), ZooDefs.Perms.ALL);
  }

}
