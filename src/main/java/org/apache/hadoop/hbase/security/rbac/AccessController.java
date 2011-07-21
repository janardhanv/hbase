/*
 * Copyright 2010 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.hbase.security.rbac;

import com.google.common.collect.ListMultimap;
import com.google.common.collect.Lists;
import com.google.common.collect.MapMaker;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.hbase.HColumnDescriptor;
import org.apache.hadoop.hbase.HConstants;
import org.apache.hadoop.hbase.HServerInfo;
import org.apache.hadoop.hbase.HTableDescriptor;
import org.apache.hadoop.hbase.KeyValue;
import org.apache.hadoop.hbase.HRegionInfo;
import org.apache.hadoop.hbase.ServerName;
import org.apache.hadoop.hbase.UnknownRegionException;
import org.apache.hadoop.hbase.catalog.CatalogTracker;
import org.apache.hadoop.hbase.catalog.MetaReader;
import org.apache.hadoop.hbase.client.Delete;
import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.client.Increment;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.Result;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.coprocessor.BaseRegionObserver;
import org.apache.hadoop.hbase.coprocessor.CoprocessorEnvironment;
import org.apache.hadoop.hbase.coprocessor.CoprocessorException;
import org.apache.hadoop.hbase.coprocessor.MasterCoprocessorEnvironment;
import org.apache.hadoop.hbase.coprocessor.MasterObserver;
import org.apache.hadoop.hbase.coprocessor.ObserverContext;
import org.apache.hadoop.hbase.coprocessor.RegionCoprocessorEnvironment;
import org.apache.hadoop.hbase.filter.CompareFilter;
import org.apache.hadoop.hbase.filter.FilterList;
import org.apache.hadoop.hbase.filter.WritableByteArrayComparable;
import org.apache.hadoop.hbase.ipc.RequestContext;
import org.apache.hadoop.hbase.regionserver.HRegion;
import org.apache.hadoop.hbase.regionserver.InternalScanner;
import org.apache.hadoop.hbase.security.AccessDeniedException;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.hadoop.security.UserGroupInformation;

import java.io.IOException;
import java.util.*;

public class AccessController extends BaseRegionObserver
    implements MasterObserver, AccessControllerProtocol {
  public static final Log LOG = LogFactory.getLog(AccessController.class);

  /**
   * Version number for AccessControllerProtocol
   */
  private static final long PROTOCOL_VERSION = 28L;

  TableAuthManager authManager = null;

  boolean isAclRegion = false;

  // defined only for Endpoint implementation, so it can have way to
  // access region services.
  private RegionCoprocessorEnvironment regionEnv;

  /** Mapping of scanner instances to the user who created them */
  private Map<InternalScanner,String> scannerOwners =
      new MapMaker().weakKeys().makeMap();

  void initialize(RegionCoprocessorEnvironment e) throws IOException {
    final HRegion region = e.getRegion();

    Map<byte[],ListMultimap<String,TablePermission>> tables =
        AccessControlLists.loadAll(region);
    // For each table, write out the table's permissions to the respective
    // znode for that table.
    for (Map.Entry<byte[],ListMultimap<String,TablePermission>> t:
      tables.entrySet()) {
      byte[] table = t.getKey();
      String tableName = Bytes.toString(table);
      ListMultimap<String,TablePermission> perms = t.getValue();
      byte[] serialized = AccessControlLists.writePermissionsAsBytes(perms,
          e.getRegion().getConf());
      this.authManager.getZKPermissionWatcher().writeToZookeeper(tableName,
        serialized);
    }
  }

  /**
   * Writes all table ACLs for the tables in the given Map up into ZooKeeper
   * znodes.
   */
  void updateACL(RegionCoprocessorEnvironment e,
      final Map<byte[], List<KeyValue>> familyMap) {
    Set<String> tableSet = new HashSet<String>();
    for (Map.Entry<byte[], List<KeyValue>> f : familyMap.entrySet()) {
      List<KeyValue> kvs = f.getValue();
      for (KeyValue kv: kvs) {
        if (Bytes.compareTo(kv.getBuffer(), kv.getFamilyOffset(),
            kv.getFamilyLength(), HConstants.CATALOG_FAMILY, 0,
            HConstants.CATALOG_FAMILY.length) == 0) {
          String tableName = Bytes.toString(kv.getRow());
          tableSet.add(tableName);
        }
      }
    }

    for (String tableName: tableSet) {
      try {
        ListMultimap<String,TablePermission> perms =
          AccessControlLists.getTablePermissions(regionEnv.getConf(), Bytes.toBytes(tableName));
        byte[] serialized = AccessControlLists.writePermissionsAsBytes(
            perms, e.getRegion().getConf());
        this.authManager.getZKPermissionWatcher().writeToZookeeper(tableName,
          serialized);
      } catch (IOException ex) {
        LOG.error("Failed updating permissions mirror for '" + tableName +
          "'", ex);
      }
    }
  }

  void updateACL(RegionCoprocessorEnvironment e, final KeyValue kv) {
    if (Bytes.compareTo(kv.getBuffer(), kv.getFamilyOffset(),
        kv.getFamilyLength(), HConstants.CATALOG_FAMILY, 0,
        HConstants.CATALOG_FAMILY.length) == 0) {
      byte[] table = kv.getRow();
      String tableName = Bytes.toString(table);

      try {
        ListMultimap<String,TablePermission> perms =
          AccessControlLists.getTablePermissions(regionEnv.getConf(), table);
        byte[] serialized = AccessControlLists.writePermissionsAsBytes(perms,
            e.getRegion().getConf());
        this.authManager.getZKPermissionWatcher().writeToZookeeper(tableName,
          serialized); 
      } catch (IOException ex) {
        LOG.error("Failed updating permissions mirror for '" + tableName +
          "'", ex);
      }
    }
  }

  /**
   * Check the current user for authorization to perform a specific action
   * against the given set of row data.
   *
   * <p>Note: Ordering of the authorization checks
   * has been carefully optimized to short-circuit the most common requests
   * and minimize the amount of processing required.</p>
   *
   * @param permRequest the action being requested
   * @param e the coprocessor environment
   * @param families the map of column families to qualifiers present in
   * the request
   * @return
   */
  boolean permissionGranted(TablePermission.Action permRequest,
      RegionCoprocessorEnvironment e,
      Map<byte [], ? extends Collection<?>> families) {
    HRegionInfo hri = e.getRegion().getRegionInfo();
    HTableDescriptor htd = e.getRegion().getTableDesc();
    byte[] tableName = hri.getTableName();

    // 1. All users need read access to .META. and -ROOT- tables.
    // this is a very common operation, so deal with it quickly.
    if ((hri.isRootRegion() || hri.isMetaRegion()) &&
        (permRequest == TablePermission.Action.READ)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("All users are allowed to " + permRequest.toString() +
          " the table '" + hri.getTableNameAsString() + "'");
      }
      return true;
    }

    UserGroupInformation user = RequestContext.getRequestUser();
    if (user == null) {
      LOG.info("No user associated with request!  Permission denied!");
      return false;
    }

    // 2. The table owner has full privileges
    String owner = htd.getOwnerString();
    if (owner == null) {
      LOG.debug("Owner of '" + hri.getTableNameAsString() + " is (incorrectly) null.");
    }
    if (user.getShortUserName().equals(owner)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("User '" + user.getShortUserName() + "' is owner: allowed to " +
          permRequest.toString() + " the table '" + hri.getTableNameAsString() +
          "'");
      }
      return true;
    }

    // 3. check for the table-level, if successful we can short-circuit
    if (authManager.authorize(user, tableName, (byte[])null, permRequest)) {
      return true;
    }

    // 4. check permissions against the requested families
    if (families != null && families.size() > 0) {
      // all families must pass
      for (Map.Entry<byte [], ? extends Collection<?>> family : families.entrySet()) {
        // a) check for family level access
        if (authManager.authorize(user, tableName, family.getKey(),
            permRequest)) {
          continue;  // family-level permission overrides per-qualifier
        }

        // b) qualifier level access can still succeed
        if ((family.getValue() != null) && (family.getValue().size() > 0)) {
          if (family.getValue() instanceof Set) {
            // for each qualifier of the family
            Set<byte[]> familySet = (Set<byte[]>)family.getValue();
            for (byte[] qualifier : familySet) {
              if (!authManager.authorize(user, tableName, family.getKey(),
                                         qualifier, permRequest)) {
                logDenied(user, tableName, family.getKey(), qualifier,
                    permRequest);
                return false;
              }
            }
          } else if (family.getValue() instanceof List) { // List<KeyValue>
            List<KeyValue> kvList = (List<KeyValue>)family.getValue();
            for (KeyValue kv : kvList) {
              if (!authManager.authorize(user, tableName, family.getKey(),
                      kv.getQualifier(), permRequest)) {
                logDenied(user, tableName, family.getKey(), kv.getQualifier(),
                    permRequest);
                return false;
              }
            }
          }
        } else {
          // no qualifiers and family-level check already failed
          logDenied(user, tableName, family.getKey(), null, permRequest);
          return false;
        }
      }

      // all family checks passed
      return true;
    }

    // 5. no families to check and table level access failed
    logDenied(user, tableName, null, null, permRequest);
    return false;
  }

  private void logDenied(UserGroupInformation user, byte[] table, byte[] family,
      byte[] qualifier, Permission.Action perm) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("User '" + user.getShortUserName() +
          "' is not allowed to have " + perm.toString() + " access to " +
          Bytes.toString(table) + "(" +
          family != null ? Bytes.toString(family) : "" +
          qualifier != null ? Bytes.toString(qualifier) : "" +
          Bytes.toString(family) + ")"  );
    }
  }

  /**
   * Authorizes that the current user has global privileges for the given action.
   * @param perm The action being requested
   * @throws IOException if obtaining the current user fails or authorization
   *     is denied
   */
  public void requirePermission(Permission.Action perm) throws IOException {
    UserGroupInformation user = RequestContext.getRequestUser();
    if (!RequestContext.isInRequestContext()) {
      // for non-rpc handling, fallback to system user
      user = UserGroupInformation.getCurrentUser();
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Checking authorization of user '" +
          (user != null ? user.getShortUserName() : "NULL") + "' for action " +
          perm.toString());
    }
    if (!authManager.authorize(user, perm)) {
      throw new AccessDeniedException("Insufficient permissions for user '" +
          (user != null ? user.getShortUserName() : "null") +"' (global, action=" +
          perm.toString() + ")");
    }
  }

  /**
   * Authorizes that the current user has permission to perform the given
   * action on the set of table column families.
   * @param perm Action that is required
   * @param env The current coprocessor environment
   * @param families The set of column families present/required in the request
   * @throws AccessDeniedException if the authorization check failed
   */
  public void requirePermission(Permission.Action perm,
        RegionCoprocessorEnvironment env, Collection<byte[]> families)
      throws IOException {
    // create a map of family-qualifier
    HashMap<byte[], Set<byte[]>> familyMap = new HashMap<byte[], Set<byte[]>>();
    for (byte[] family : families) {
      familyMap.put(family, null);
    }
    requirePermission(perm, env, familyMap);
  }

  /**
   * Authorizes that the current user has permission to perform the given
   * action on the set of table column families.
   * @param perm Action that is required
   * @param env The current coprocessor environment
   * @param families The map of column families-qualifiers.
   * @throws AccessDeniedException if the authorization check failed
   */
  public void requirePermission(Permission.Action perm,
        RegionCoprocessorEnvironment env,
        Map<byte[], ? extends Collection<?>> families)
      throws IOException {
    if (!permissionGranted(perm, env, families)) {
      StringBuffer sb = new StringBuffer("");
      if ((families != null && families.size() > 0)) {
        for (byte[] familyName : families.keySet()) {
          if (sb.length() != 0) {
            sb.append(", ");
          }
          sb.append(Bytes.toString(familyName));
        }
      }
      throw new AccessDeniedException("Insufficient permissions (table=" +
        env.getRegion().getTableDesc().getNameAsString()+
        ((families != null && families.size() > 0) ? ", family: " +
        sb.toString() : "") + ", action=" +
        perm.toString() + ")");
    }
  }

  /**
   * Returns <code>true</code> if the current user is allowed the given action
   * over at least one of the column qualifiers in the given column families.
   */
  public boolean hasFamilyQualifierPermission(TablePermission.Action perm,
      RegionCoprocessorEnvironment env,
      Map<byte[], ? extends Set<byte[]>> familyMap)
    throws IOException {
    HRegionInfo hri = env.getRegion().getRegionInfo();
    byte[] tableName = hri.getTableName();

    UserGroupInformation user = RequestContext.getRequestUser();
    if (user == null) {
      LOG.info("No user associated with request. Permission denied!");
      return false;
    }

    if (familyMap != null && familyMap.size() > 0) {
      // at least one family must be allowed
      for (Map.Entry<byte[], ? extends Set<byte[]>> family :
          familyMap.entrySet()) {
        if (family.getValue() != null && !family.getValue().isEmpty()) {
          for (byte[] qualifier : family.getValue()) {
            if (authManager.matchPermission(user, tableName,
                family.getKey(), qualifier, perm)) {
              return true;
            }
          }
        } else {
          if (authManager.matchPermission(user, tableName, family.getKey(),
              perm)) {
            return true;
          }
        }
      }
    } else if (LOG.isDebugEnabled()) {
      LOG.debug("Empty family map passed for permission check");
    }

    return false;
  }

  /* ---- MasterObserver implementation ---- */
  public void start(CoprocessorEnvironment env) {
    // if running on HMaster
    if (env instanceof MasterCoprocessorEnvironment) {
      MasterCoprocessorEnvironment e = (MasterCoprocessorEnvironment)env;
      this.authManager = TableAuthManager.get(
          e.getMasterServices().getZooKeeper(),
          e.getConf());
    }

    // if running at region
    if (env instanceof RegionCoprocessorEnvironment) {
      regionEnv = (RegionCoprocessorEnvironment)env;
    }
  }

  public void stop(CoprocessorEnvironment env) {

  }

  @Override
  public void preCreateTable(ObserverContext<MasterCoprocessorEnvironment> c,
      HTableDescriptor desc, byte[][] splitKeys) throws IOException {
    requirePermission(Permission.Action.CREATE);
  }
  @Override
  public void postCreateTable(ObserverContext<MasterCoprocessorEnvironment> c,
      HRegionInfo[] regions, boolean sync) throws IOException {}

  @Override
  public void preDeleteTable(ObserverContext<MasterCoprocessorEnvironment> c,
      byte[] tableName) throws IOException {
    requirePermission(Permission.Action.CREATE);
  }
  @Override
  public void postDeleteTable(ObserverContext<MasterCoprocessorEnvironment> c,
      byte[] tableName) throws IOException {}


  @Override
  public void preModifyTable(ObserverContext<MasterCoprocessorEnvironment> c,
      byte[] tableName, HTableDescriptor htd) throws IOException {
    requirePermission(Permission.Action.CREATE);
  }
  @Override
  public void postModifyTable(ObserverContext<MasterCoprocessorEnvironment> c,
      byte[] tableName, HTableDescriptor htd) throws IOException {}


  @Override
  public void preAddColumn(ObserverContext<MasterCoprocessorEnvironment> c,
      byte[] tableName, HColumnDescriptor column) throws IOException {
    requirePermission(Permission.Action.CREATE);
  }
  @Override
  public void postAddColumn(ObserverContext<MasterCoprocessorEnvironment> c,
      byte[] tableName, HColumnDescriptor column) throws IOException {}


  @Override
  public void preModifyColumn(ObserverContext<MasterCoprocessorEnvironment> c,
      byte[] tableName, HColumnDescriptor descriptor) throws IOException {
    requirePermission(Permission.Action.CREATE);
  }
  @Override
  public void postModifyColumn(ObserverContext<MasterCoprocessorEnvironment> c,
      byte[] tableName, HColumnDescriptor descriptor) throws IOException {}


  @Override
  public void preDeleteColumn(ObserverContext<MasterCoprocessorEnvironment> c,
      byte[] tableName, byte[] col) throws IOException {
    requirePermission(Permission.Action.CREATE);
  }
  @Override
  public void postDeleteColumn(ObserverContext<MasterCoprocessorEnvironment> c,
      byte[] tableName, byte[] col) throws IOException {}


  @Override
  public void preEnableTable(ObserverContext<MasterCoprocessorEnvironment> c,
      byte[] tableName) throws IOException {
    // TODO: enable/disable required to alter a table, should ADMIN be required here?
    requirePermission(Permission.Action.ADMIN);
  }
  @Override
  public void postEnableTable(ObserverContext<MasterCoprocessorEnvironment> c,
      byte[] tableName) throws IOException {}

  @Override
  public void preDisableTable(ObserverContext<MasterCoprocessorEnvironment> c,
      byte[] tableName) throws IOException {
    // TODO: enable/disable required to alter a table, should ADMIN be required here?
    requirePermission(Permission.Action.ADMIN);
  }
  @Override
  public void postDisableTable(ObserverContext<MasterCoprocessorEnvironment> c,
      byte[] tableName) throws IOException {}

  @Override
  public void preMove(ObserverContext<MasterCoprocessorEnvironment> c,
      HRegionInfo region, ServerName srcServer, ServerName destServer)
    throws IOException {
    requirePermission(Permission.Action.ADMIN);
  }
  @Override
  public void postMove(ObserverContext<MasterCoprocessorEnvironment> c,
      HRegionInfo region, ServerName srcServer, ServerName destServer)
    throws UnknownRegionException {}

  @Override
  public void preAssign(ObserverContext<MasterCoprocessorEnvironment> c,
      byte[] regionName, boolean force) throws IOException {
    requirePermission(Permission.Action.ADMIN);
  }
  @Override
  public void postAssign(ObserverContext<MasterCoprocessorEnvironment> c,
      HRegionInfo regionInfo) throws IOException {}

  @Override
  public void preUnassign(ObserverContext<MasterCoprocessorEnvironment> c,
      byte[] regionName, boolean force) throws IOException {
    requirePermission(Permission.Action.ADMIN);
  }
  @Override
  public void postUnassign(ObserverContext<MasterCoprocessorEnvironment> c,
      HRegionInfo regionInfo, boolean force) throws IOException {}

  @Override
  public void preBalance(ObserverContext<MasterCoprocessorEnvironment> c)
      throws IOException {
    requirePermission(Permission.Action.ADMIN);
  }
  @Override
  public void postBalance(ObserverContext<MasterCoprocessorEnvironment> c)
      throws IOException {}

  @Override
  public boolean preBalanceSwitch(ObserverContext<MasterCoprocessorEnvironment> c,
      boolean newValue) throws IOException {
    requirePermission(Permission.Action.ADMIN);
    return newValue;
  }
  @Override
  public void postBalanceSwitch(ObserverContext<MasterCoprocessorEnvironment> c,
      boolean oldValue, boolean newValue) throws IOException {}

  @Override
  public void preShutdown(ObserverContext<MasterCoprocessorEnvironment> c)
      throws IOException {
    requirePermission(Permission.Action.ADMIN);
  }

  @Override
  public void preStopMaster(ObserverContext<MasterCoprocessorEnvironment> c)
      throws IOException {
    requirePermission(Permission.Action.ADMIN);
  }

  @Override
  public void postStartMaster(ObserverContext<MasterCoprocessorEnvironment> ctx)
      throws IOException {
    // initialize the ACL storage table
    AccessControlLists.init(ctx.getEnvironment().getMasterServices());
  }


  /* ---- RegionObserver implementation ---- */

  @Override
  public void postOpen(ObserverContext<RegionCoprocessorEnvironment> c) {
    RegionCoprocessorEnvironment e = c.getEnvironment();
    final HRegion region = e.getRegion();
    HRegionInfo regionInfo = null;
    if (region != null) {
      regionInfo = region.getRegionInfo();
    } else {
      LOG.warn("NULL region from RegionCoprocessorEnvironment in postOpen()");
      return;
    }

    this.authManager = TableAuthManager.get(
        e.getRegionServerServices().getZooKeeper(),
        e.getRegion().getConf());

    if (regionInfo.isRootRegion() || regionInfo.isMetaRegion()) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Opening -ROOT- or .META., no op");
      }
      return;
    }

    if (AccessControlLists.isAclRegion(region)) {
      isAclRegion = true;
      try {
        initialize(e);
      } catch (IOException ex) {
        LOG.error("Failed to initialize permissions mirror", ex);
      }
    }
  }

  @Override
  public void preGetClosestRowBefore(final ObserverContext<RegionCoprocessorEnvironment> c,
      final byte [] row, final byte [] family, final Result result)
      throws IOException {
    requirePermission(TablePermission.Action.READ, c.getEnvironment(),
        (family != null ? Lists.newArrayList(family) : null));
  }

  @Override
  public void preGet(final ObserverContext<RegionCoprocessorEnvironment> c, final Get get,
      final List<KeyValue> result) throws IOException {
    /*
     if column family level checks fail, check for a qualifier level permission
     in one of the families.  If it is present, then continue with the AccessControlFilter.
      */
    RegionCoprocessorEnvironment e = c.getEnvironment();
    if (!permissionGranted(TablePermission.Action.READ, e,
        get.getFamilyMap())) {
      if (hasFamilyQualifierPermission(TablePermission.Action.READ, e,
          get.getFamilyMap())) {
        byte[] table = getTableName(e);
        AccessControlFilter filter = new AccessControlFilter(authManager,
            UserGroupInformation.getCurrentUser(), table);

        // wrap any existing filter
        if (get.getFilter() != null) {
          FilterList wrapper = new FilterList(FilterList.Operator.MUST_PASS_ALL,
              Lists.newArrayList(filter, get.getFilter()));
          get.setFilter(wrapper);
        } else {
          get.setFilter(filter);
        }
      } else {
        throw new AccessDeniedException("Insufficient permissions (table=" +
          e.getRegion().getTableDesc().getNameAsString() + ", action=READ)");
      }
    }
  }

  @Override
  public boolean preExists(final ObserverContext<RegionCoprocessorEnvironment> c, final Get get,
      final boolean exists) throws IOException {
    requirePermission(TablePermission.Action.READ, c.getEnvironment(), get.familySet());
    return exists;
  }

  @Override
  public void prePut(final ObserverContext<RegionCoprocessorEnvironment> c,
      final Map<byte[], List<KeyValue>> familyMap, final boolean writeToWAL)
      throws IOException {
    requirePermission(TablePermission.Action.WRITE, c.getEnvironment(),
        familyMap);
  }

  @Override
  public void postPut(final ObserverContext<RegionCoprocessorEnvironment> c,
      final Map<byte[], List<KeyValue>> familyMap, final boolean writeToWAL) {
    if (isAclRegion) {
      updateACL(c.getEnvironment(), familyMap);
    }
  }

  @Override
  public void preDelete(final ObserverContext<RegionCoprocessorEnvironment> c,
      final Map<byte[], List<KeyValue>> familyMap, final boolean writeToWAL)
      throws IOException {
    requirePermission(TablePermission.Action.WRITE, c.getEnvironment(),
        familyMap);
  }

  @Override
  public void postDelete(final ObserverContext<RegionCoprocessorEnvironment> c,
      final Map<byte[], List<KeyValue>> familyMap, final boolean writeToWAL)
      throws IOException {
    if (isAclRegion) {
      updateACL(c.getEnvironment(), familyMap);
    }
  }

  @Override
  public boolean preCheckAndPut(final ObserverContext<RegionCoprocessorEnvironment> c,
      final byte [] row, final byte [] family, final byte [] qualifier,
      final CompareFilter.CompareOp compareOp,
      final WritableByteArrayComparable comparator, final Put put,
      final boolean result) throws IOException {
    requirePermission(TablePermission.Action.READ, c.getEnvironment(),
        Arrays.asList(new byte[][]{family}));
    return result;
  }

  @Override
  public boolean preCheckAndDelete(final ObserverContext<RegionCoprocessorEnvironment> c,
      final byte [] row, final byte [] family, final byte [] qualifier,
      final CompareFilter.CompareOp compareOp,
      final WritableByteArrayComparable comparator, final Delete delete,
      final boolean result) throws IOException {
    requirePermission(TablePermission.Action.READ, c.getEnvironment(),
        Arrays.asList( new byte[][] {family}));
    return result;
  }

  @Override
  public long preIncrementColumnValue(final ObserverContext<RegionCoprocessorEnvironment> c,
      final byte [] row, final byte [] family, final byte [] qualifier,
      final long amount, final boolean writeToWAL)
      throws IOException {
    requirePermission(TablePermission.Action.WRITE, c.getEnvironment(),
        Arrays.asList(new byte[][]{family}));
    return -1;
  }

  @Override
  public void preIncrement(final ObserverContext<RegionCoprocessorEnvironment> c,
      final Increment increment, final Result result)
      throws IOException {
    requirePermission(TablePermission.Action.WRITE, c.getEnvironment(),
        increment.getFamilyMap().keySet());
  }

  @Override
  public InternalScanner preScannerOpen(final ObserverContext<RegionCoprocessorEnvironment> c,
      final Scan scan, final InternalScanner s) throws IOException {
    /*
     if column family level checks fail, check for a qualifier level permission
     in one of the families.  If it is present, then continue with the AccessControlFilter.
      */
    RegionCoprocessorEnvironment e = c.getEnvironment();
    UserGroupInformation user = RequestContext.getRequestUser();
    if (!permissionGranted(TablePermission.Action.READ, e, scan.getFamilyMap())) {
      if (hasFamilyQualifierPermission(TablePermission.Action.READ, e,
          scan.getFamilyMap())) {
        byte[] table = getTableName(e);
        AccessControlFilter filter = new AccessControlFilter(authManager,
            user, table);

        // wrap any existing filter
        if (scan.hasFilter()) {
          FilterList wrapper = new FilterList(FilterList.Operator.MUST_PASS_ALL,
              Lists.newArrayList(filter, scan.getFilter()));
          scan.setFilter(wrapper);
        } else {
          scan.setFilter(filter);
        }
      } else {
        // no table/family level perms and no qualifier level perms, reject
        throw new AccessDeniedException("Insufficient permissions for user '"+
            (user != null ? user.getShortUserName() : "null")+"' "+
            "for scanner open on table " + Bytes.toString(getTableName(e)));
      }
    }
    return s;
  }

  @Override
  public InternalScanner postScannerOpen(final ObserverContext<RegionCoprocessorEnvironment> c,
      final Scan scan, final InternalScanner s) throws IOException {
    UserGroupInformation user = RequestContext.getRequestUser();
    if (user != null && user.getShortUserName() != null) {
      // store reference to scanner owner for later checks
      scannerOwners.put(s, user.getShortUserName());
    }
    return s;
  }

  @Override
  public boolean preScannerNext(final ObserverContext<RegionCoprocessorEnvironment> c,
      final InternalScanner s, final List<Result> result,
      final int limit, final boolean hasNext) throws IOException {
    // verify that requesting user matches the user who created the scanner
    // if so, we assume that access control is correctly enforced based on
    // the checks performed in preScannerOpen()
    if (RequestContext.isInRequestContext()) {
      String owner = scannerOwners.get(s);
      if (owner != null && !owner.equals(RequestContext.getRequestUserName())) {
        throw new AccessDeniedException("User '"+
            RequestContext.getRequestUserName()+"' is not the scanner owner!");
      }
    }
    return hasNext;
  }

  @Override
  public void preScannerClose(final ObserverContext<RegionCoprocessorEnvironment> c,
      final InternalScanner s) throws IOException {
    // Verify, when called through RPC, that the caller is the scanner owner
    if (RequestContext.isInRequestContext()) {
      String owner = scannerOwners.get(s);
      if (owner != null && !owner.equals(RequestContext.getRequestUserName())) {
        throw new AccessDeniedException("User '"+
            RequestContext.getRequestUserName()+"' is not the scanner owner!");
      }
    }
  }

  @Override
  public void postScannerClose(final ObserverContext<RegionCoprocessorEnvironment> c,
      final InternalScanner s) throws IOException {
    // clean up any associated owner mapping
    scannerOwners.remove(s);
  }

  // the following endpoint methods are provided for grant/revoke/list
  // permissions from client side. They're suppose to be executed only
  // at the .META. region. This restriction will be applied by both client
  // side and endpoint implementation.
  @Override
  public boolean grant(byte[] user, TablePermission permission)
      throws IOException {
    // verify it's only running at .acl.
    if (isAclRegion) {
      LOG.info("Receive request to grant access permission to '"
          + Bytes.toString(user) + "'. "
          + permission.toString());

      requirePermission(Permission.Action.ADMIN);

      AccessControlLists.addTablePermission(regionEnv.getConf(),
          permission.getTable(), Bytes.toString(user), permission);
      LOG.info("Grant permission successfully.");
    } else {
      throw new CoprocessorException(AccessController.class, "This method " +
          "can only execute at " +
          Bytes.toString(AccessControlLists.ACL_TABLE_NAME) + " table.");
    }
    return true;
  }

  @Override
  public boolean revoke(byte[] user, TablePermission permission)
      throws IOException{
    // only allowed to be called on _acl_ region
    if (isAclRegion) {
      LOG.info("Receive request to revoke access permission for '"
          + Bytes.toString(user) + "'. "
          + permission.toString());

      requirePermission(Permission.Action.ADMIN);

      AccessControlLists.removeTablePermission(regionEnv.getConf(),
          permission.getTable(), Bytes.toString(user), permission);
      LOG.info("Revoke permission successfully.");
    } else {
      throw new CoprocessorException(AccessController.class, "This method " +
          "can only execute at " +
          Bytes.toString(AccessControlLists.ACL_TABLE_NAME) + " table.");
    }
    return true;
  }

  @Override
  public List<UserPermission> getUserPermissions(final byte[] tableName)
      throws IOException {
    // only allowed to be called on _acl_ region
    if (isAclRegion) {
      requirePermission(Permission.Action.ADMIN);

      List<UserPermission> perms = AccessControlLists.getUserPermissions
          (regionEnv.getConf(), tableName);
      return perms;
    } else {
      throw new CoprocessorException(AccessController.class, "This method " +
          "can only execute at " +
          Bytes.toString(AccessControlLists.ACL_TABLE_NAME) + " table.");
    }
  }

  @Override
  public long getProtocolVersion(String protocol, long clientVersion) throws IOException {
    return PROTOCOL_VERSION;
  }

  /**
   * @param e Coprocessor environment.
   */
  private void setEnvironment(RegionCoprocessorEnvironment e) {
    regionEnv = e;
  }

  /**
   * @return env Coprocessor environment.
   */
  public RegionCoprocessorEnvironment getEnvironment() {
    return regionEnv;
  }

  public byte[] getTableName(RegionCoprocessorEnvironment e) {
    HRegion region = e.getRegion();
    byte[] tableName = null;

    if (region != null) {
      HRegionInfo regionInfo = region.getRegionInfo();
      if (regionInfo != null) {
        tableName = regionInfo.getTableName();
      }
    }
    return tableName;
  }
}
