package org.apache.hadoop.hbase.security.rbac;

import java.io.IOException;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.ipc.SecureRpcEngine;
import org.apache.hadoop.hbase.security.User;

/**
 * Utility methods for testing security
 */
public class SecureTestUtil {
  public static void enableSecurity(Configuration conf) throws IOException {
    conf.set("hadoop.security.authorization", "false");
    conf.set("hadoop.security.authentication", "simple");
    conf.set("hbase.rpc.engine", SecureRpcEngine.class.getName());
    conf.set("hbase.coprocessor.master.classes", AccessController.class.getName());
    conf.set("hbase.coprocessor.region.classes", AccessController.class.getName());
    // add the process running user to superusers
    String currentUser = User.getCurrent().getName();
    conf.set("hbase.superuser", "admin,"+currentUser);
  }
}
