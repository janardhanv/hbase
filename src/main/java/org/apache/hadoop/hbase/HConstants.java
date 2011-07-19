/**
 * Copyright 2010 The Apache Software Foundation
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
package org.apache.hadoop.hbase;

import org.apache.hadoop.hbase.ipc.HRegionInterface;
import org.apache.hadoop.hbase.util.Bytes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * HConstants holds a bunch of HBase-related constants
 */
public final class HConstants {
  /**
   * Status codes used for return values of bulk operations.
   */
  public enum OperationStatusCode {
    NOT_RUN,
    SUCCESS,
    BAD_FAMILY,
    FAILURE;
  }

  /** long constant for zero */
  public static final Long ZERO_L = Long.valueOf(0L);
  public static final String NINES = "99999999999999";
  public static final String ZEROES = "00000000000000";

  // For migration

  /** name of version file */
  public static final String VERSION_FILE_NAME = "hbase.version";

  /**
   * Current version of file system.
   * Version 4 supports only one kind of bloom filter.
   * Version 5 changes versions in catalog table regions.
   * Version 6 enables blockcaching on catalog tables.
   * Version 7 introduces hfile -- hbase 0.19 to 0.20..
   */
  // public static final String FILE_SYSTEM_VERSION = "6";
  public static final String FILE_SYSTEM_VERSION = "7";

  // Configuration parameters

  //TODO: Is having HBase homed on port 60k OK?

  /** Cluster is in distributed mode or not */
  public static final String CLUSTER_DISTRIBUTED = "hbase.cluster.distributed";

  /** Cluster is standalone or pseudo-distributed */
  public static final String CLUSTER_IS_LOCAL = "false";

  /** Cluster is fully-distributed */
  public static final String CLUSTER_IS_DISTRIBUTED = "true";

  /** default host address */
  public static final String DEFAULT_HOST = "0.0.0.0";

  /** Parameter name for port master listens on. */
  public static final String MASTER_PORT = "hbase.master.port";

  /** default port that the master listens on */
  public static final int DEFAULT_MASTER_PORT = 60000;

  /** default port for master web api */
  public static final int DEFAULT_MASTER_INFOPORT = 60010;

  /** Parameter name for the master type being backup (waits for primary to go inactive). */
  public static final String MASTER_TYPE_BACKUP = "hbase.master.backup";

  /** by default every master is a possible primary master unless the conf explicitly overrides it */
  public static final boolean DEFAULT_MASTER_TYPE_BACKUP = false;

  /** Name of ZooKeeper quorum configuration parameter. */
  public static final String ZOOKEEPER_QUORUM = "hbase.zookeeper.quorum";

  /** Name of ZooKeeper config file in conf/ directory. */
  public static final String ZOOKEEPER_CONFIG_NAME = "zoo.cfg";

  /** Parameter name for the client port that the zookeeper listens on */
  public static final String ZOOKEEPER_CLIENT_PORT = "hbase.zookeeper.property.clientPort";

  /** Default client port that the zookeeper listens on */
  public static final int DEFAULT_ZOOKEPER_CLIENT_PORT = 2181;

  /** Parameter name for the wait time for the recoverable zookeeper */
  public static final String ZOOKEEPER_RECOVERABLE_WAITTIME = "hbase.zookeeper.recoverable.waittime";

  /** Default wait time for the recoverable zookeeper */
  public static final long DEFAULT_ZOOKEPER_RECOVERABLE_WAITIME = 10000;

  /** Parameter name for the root dir in ZK for this cluster */
  public static final String ZOOKEEPER_ZNODE_PARENT = "zookeeper.znode.parent";

  public static final String DEFAULT_ZOOKEEPER_ZNODE_PARENT = "/hbase";

  /** Parameter name for the limit on concurrent client-side zookeeper connections */
  public static final String ZOOKEEPER_MAX_CLIENT_CNXNS = "hbase.zookeeper.property.maxClientCnxns";

  /** Default limit on concurrent client-side zookeeper connections */
  public static final int DEFAULT_ZOOKEPER_MAX_CLIENT_CNXNS = 30;

  /** Parameter name for port region server listens on. */
  public static final String REGIONSERVER_PORT = "hbase.regionserver.port";

  /** Default port region server listens on. */
  public static final int DEFAULT_REGIONSERVER_PORT = 60020;

  /** default port for region server web api */
  public static final int DEFAULT_REGIONSERVER_INFOPORT = 60030;

  /** Parameter name for what region server interface to use. */
  public static final String REGION_SERVER_CLASS = "hbase.regionserver.class";

  /** Parameter name for what region server implementation to use. */
  public static final String REGION_SERVER_IMPL= "hbase.regionserver.impl";

  /** Default region server interface class name. */
  public static final String DEFAULT_REGION_SERVER_CLASS = HRegionInterface.class.getName();

  /** Parameter name for what master implementation to use. */
  public static final String MASTER_IMPL= "hbase.master.impl";

  /** Parameter name for how often threads should wake up */
  public static final String THREAD_WAKE_FREQUENCY = "hbase.server.thread.wakefrequency";

  /** Default value for thread wake frequency */
  public static final int DEFAULT_THREAD_WAKE_FREQUENCY = 10 * 1000;

  /** Parameter name for how often a region should should perform a major compaction */
  public static final String MAJOR_COMPACTION_PERIOD = "hbase.hregion.majorcompaction";

  /** Parameter name for HBase instance root directory */
  public static final String HBASE_DIR = "hbase.rootdir";

  /** Parameter name for HBase client IPC pool type */
  public static final String HBASE_CLIENT_IPC_POOL_TYPE = "hbase.client.ipc.pool.type";

  /** Parameter name for HBase client IPC pool size */
  public static final String HBASE_CLIENT_IPC_POOL_SIZE = "hbase.client.ipc.pool.size";

  /** Parameter name for HBase client operation timeout, which overrides RPC timeout */
  public static final String HBASE_CLIENT_OPERATION_TIMEOUT = "hbase.client.operation.timeout";

  /** Default HBase client operation timeout, which is tantamount to a blocking call */
  public static final int DEFAULT_HBASE_CLIENT_OPERATION_TIMEOUT = Integer.MAX_VALUE;

  /** Used to construct the name of the log directory for a region server
   * Use '.' as a special character to seperate the log files from table data */
  public static final String HREGION_LOGDIR_NAME = ".logs";

  /** Used to construct the name of the splitlog directory for a region server */
  public static final String SPLIT_LOGDIR_NAME = "splitlog";

  public static final String CORRUPT_DIR_NAME = ".corrupt";

  /** Like the previous, but for old logs that are about to be deleted */
  public static final String HREGION_OLDLOGDIR_NAME = ".oldlogs";

  /** Used to construct the name of the compaction directory during compaction */
  public static final String HREGION_COMPACTIONDIR_NAME = "compaction.dir";

  /** The file name used to store HTD in HDFS  */
  public static final String TABLEINFO_NAME = ".tableinfo";

  /** The metaupdated column qualifier */
  public static final byte [] META_MIGRATION_QUALIFIER = Bytes.toBytes("metamigrated");


  /** Default maximum file size */
  public static final long DEFAULT_MAX_FILE_SIZE = 256 * 1024 * 1024;

  /** Default size of a reservation block   */
  public static final int DEFAULT_SIZE_RESERVATION_BLOCK = 1024 * 1024 * 5;

  /** Maximum value length, enforced on KeyValue construction */
  public static final int MAXIMUM_VALUE_LENGTH = Integer.MAX_VALUE;

  /** name of the file for unique cluster ID */
  public static final String CLUSTER_ID_FILE_NAME = "hbase.id";

  /** Configuration key storing the cluster ID */
  public static final String CLUSTER_ID = "hbase.cluster.id";

  // Always store the location of the root table's HRegion.
  // This HRegion is never split.

  // region name = table + startkey + regionid. This is the row key.
  // each row in the root and meta tables describes exactly 1 region
  // Do we ever need to know all the information that we are storing?

  // Note that the name of the root table starts with "-" and the name of the
  // meta table starts with "." Why? it's a trick. It turns out that when we
  // store region names in memory, we use a SortedMap. Since "-" sorts before
  // "." (and since no other table name can start with either of these
  // characters, the root region will always be the first entry in such a Map,
  // followed by all the meta regions (which will be ordered by their starting
  // row key as well), followed by all user tables. So when the Master is
  // choosing regions to assign, it will always choose the root region first,
  // followed by the meta regions, followed by user regions. Since the root
  // and meta regions always need to be on-line, this ensures that they will
  // be the first to be reassigned if the server(s) they are being served by
  // should go down.


  //
  // New stuff.  Making a slow transition.
  //

  /** The root table's name.*/
  public static final byte [] ROOT_TABLE_NAME = Bytes.toBytes("-ROOT-");

  /** The META table's name. */
  public static final byte [] META_TABLE_NAME = Bytes.toBytes(".META.");

  /** delimiter used between portions of a region name */
  public static final int META_ROW_DELIMITER = ',';

  /** The catalog family as a string*/
  public static final String CATALOG_FAMILY_STR = "info";

  /** The catalog family */
  public static final byte [] CATALOG_FAMILY = Bytes.toBytes(CATALOG_FAMILY_STR);

  /** The regioninfo column qualifier */
  public static final byte [] REGIONINFO_QUALIFIER = Bytes.toBytes("regioninfo");

  /** The server column qualifier */
  public static final byte [] SERVER_QUALIFIER = Bytes.toBytes("server");

  /** The startcode column qualifier */
  public static final byte [] STARTCODE_QUALIFIER = Bytes.toBytes("serverstartcode");

  /** The lower-half split region column qualifier */
  public static final byte [] SPLITA_QUALIFIER = Bytes.toBytes("splitA");

  /** The upper-half split region column qualifier */
  public static final byte [] SPLITB_QUALIFIER = Bytes.toBytes("splitB");

  // Other constants

  /**
   * An empty instance.
   */
  public static final byte [] EMPTY_BYTE_ARRAY = new byte [0];

  /**
   * Used by scanners, etc when they want to start at the beginning of a region
   */
  public static final byte [] EMPTY_START_ROW = EMPTY_BYTE_ARRAY;

  /**
   * Last row in a table.
   */
  public static final byte [] EMPTY_END_ROW = EMPTY_START_ROW;

  /**
    * Used by scanners and others when they're trying to detect the end of a
    * table
    */
  public static final byte [] LAST_ROW = EMPTY_BYTE_ARRAY;

  /**
   * Max length a row can have because of the limitation in TFile.
   */
  public static final int MAX_ROW_LENGTH = Short.MAX_VALUE;

  /** When we encode strings, we always specify UTF8 encoding */
  public static final String UTF8_ENCODING = "UTF-8";

  /**
   * Timestamp to use when we want to refer to the latest cell.
   * This is the timestamp sent by clients when no timestamp is specified on
   * commit.
   */
  public static final long LATEST_TIMESTAMP = Long.MAX_VALUE;

  /**
   * Timestamp to use when we want to refer to the oldest cell.
   */
  public static final long OLDEST_TIMESTAMP = Long.MIN_VALUE;

  /**
   * LATEST_TIMESTAMP in bytes form
   */
  public static final byte [] LATEST_TIMESTAMP_BYTES = Bytes.toBytes(LATEST_TIMESTAMP);

  /**
   * Define for 'return-all-versions'.
   */
  public static final int ALL_VERSIONS = Integer.MAX_VALUE;

  /**
   * Unlimited time-to-live.
   */
//  public static final int FOREVER = -1;
  public static final int FOREVER = Integer.MAX_VALUE;

  /**
   * Seconds in a week
   */
  public static final int WEEK_IN_SECONDS = 7 * 24 * 3600;

  //TODO: although the following are referenced widely to format strings for
  //      the shell. They really aren't a part of the public API. It would be
  //      nice if we could put them somewhere where they did not need to be
  //      public. They could have package visibility
  public static final String NAME = "NAME";
  public static final String VERSIONS = "VERSIONS";
  public static final String IN_MEMORY = "IN_MEMORY";

  // for access control implementation.
  public static final String OWNER = "OWNER";

  /**
   * This is a retry backoff multiplier table similar to the BSD TCP syn
   * backoff table, a bit more aggressive than simple exponential backoff.
   */
  public static int RETRY_BACKOFF[] = { 1, 1, 1, 2, 2, 4, 4, 8, 16, 32 };

  public static final String REGION_IMPL = "hbase.hregion.impl";

  /** modifyTable op for replacing the table descriptor */
  public static enum Modify {
    CLOSE_REGION,
    TABLE_COMPACT,
    TABLE_FLUSH,
    TABLE_MAJOR_COMPACT,
    TABLE_SET_HTD,
    TABLE_SPLIT
  }

  /**
   * Scope tag for locally scoped data.
   * This data will not be replicated.
   */
  public static final int REPLICATION_SCOPE_LOCAL = 0;

  /**
   * Scope tag for globally scoped data.
   * This data will be replicated to all peers.
   */
  public static final int REPLICATION_SCOPE_GLOBAL = 1;

  /**
   * Default cluster ID, cannot be used to identify a cluster so a key with
   * this value means it wasn't meant for replication.
   */
  public static final byte DEFAULT_CLUSTER_ID = 0;

    /**
     * Parameter name for maximum number of bytes returned when calling a
     * scanner's next method.
     */
  public static String HBASE_CLIENT_SCANNER_MAX_RESULT_SIZE_KEY = "hbase.client.scanner.max.result.size";

  /**
   * Maximum number of bytes returned when calling a scanner's next method.
   * Note that when a single row is larger than this limit the row is still
   * returned completely.
   *
   * The default value is unlimited.
   */
  public static long DEFAULT_HBASE_CLIENT_SCANNER_MAX_RESULT_SIZE = Long.MAX_VALUE;

  /**
   * Parameter name for client pause value, used mostly as value to wait
   * before running a retry of a failed get, region lookup, etc.
   */
  public static String HBASE_CLIENT_PAUSE = "hbase.client.pause";

  /**
   * Default value of {@link #HBASE_CLIENT_PAUSE}.
   */
  public static long DEFAULT_HBASE_CLIENT_PAUSE = 1000;

  /**
   * Parameter name for maximum retries, used as maximum for all retryable
   * operations such as fetching of the root region from root region server,
   * getting a cell's value, starting a row update, etc.
   */
  public static String HBASE_CLIENT_RETRIES_NUMBER = "hbase.client.retries.number";

  /**
   * Default value of {@link #HBASE_CLIENT_RETRIES_NUMBER}.
   */
  public static int DEFAULT_HBASE_CLIENT_RETRIES_NUMBER = 10;

  /**
   * Parameter name for maximum attempts, used to limit the number of times the
   * client will try to obtain the proxy for a given region server.
   */
  public static String HBASE_CLIENT_RPC_MAXATTEMPTS = "hbase.client.rpc.maxattempts";

  /**
   * Default value of {@link #HBASE_CLIENT_RPC_MAXATTEMPTS}.
   */
  public static int DEFAULT_HBASE_CLIENT_RPC_MAXATTEMPTS = 1;

  /**
   * Parameter name for client prefetch limit, used as the maximum number of regions
   * info that will be prefetched.
   */
  public static String HBASE_CLIENT_PREFETCH_LIMIT = "hbase.client.prefetch.limit";

  /**
   * Default value of {@link #HBASE_CLIENT_PREFETCH_LIMIT}.
   */
  public static int DEFAULT_HBASE_CLIENT_PREFETCH_LIMIT = 10;

  /**
   * Parameter name for number of rows that will be fetched when calling next on
   * a scanner if it is not served from memory. Higher caching values will
   * enable faster scanners but will eat up more memory and some calls of next
   * may take longer and longer times when the cache is empty.
   */
  public static String HBASE_META_SCANNER_CACHING = "hbase.meta.scanner.caching";

  /**
   * Default value of {@link #HBASE_META_SCANNER_CACHING}.
   */
  public static int DEFAULT_HBASE_META_SCANNER_CACHING = 100;

  /**
   * Parameter name for unique identifier for this {@link Configuration}
   * instance. If there are two or more {@link Configuration} instances that,
   * for all intents and purposes, are the same except for their instance ids,
   * then they will not be able to share the same {@link Connection} instance.
   * On the other hand, even if the instance ids are the same, it could result
   * in non-shared {@link Connection} instances if some of the other connection
   * parameters differ.
   */
  public static String HBASE_CLIENT_INSTANCE_ID = "hbase.client.instance.id";

  /**
   * HRegion server lease period in milliseconds. Clients must report in within this period
   * else they are considered dead. Unit measured in ms (milliseconds).
   */
  public static String HBASE_REGIONSERVER_LEASE_PERIOD_KEY =
    "hbase.regionserver.lease.period";

  /**
   * Default value of {@link #HBASE_REGIONSERVER_LEASE_PERIOD_KEY}.
   */
  public static long DEFAULT_HBASE_REGIONSERVER_LEASE_PERIOD = 60000;

  /**
   * timeout for each RPC
   */
  public static String HBASE_RPC_TIMEOUT_KEY = "hbase.rpc.timeout";

  /**
   * Default value of {@link #HBASE_RPC_TIMEOUT_KEY}
   */
  public static int DEFAULT_HBASE_RPC_TIMEOUT = 60000;

  public static final String
      REPLICATION_ENABLE_KEY = "hbase.replication";

  /** HBCK special code name used as server name when manipulating ZK nodes */
  public static final String HBCK_CODE_NAME = "HBCKServerName";

  public static final ServerName HBCK_CODE_SERVERNAME =
    new ServerName(HBCK_CODE_NAME, -1, -1L);

  public static final String KEY_FOR_HOSTNAME_SEEN_BY_MASTER =
    "hbase.regionserver.hostname.seen.by.master";

  public static final String HBASE_MASTER_LOGCLEANER_PLUGINS =
      "hbase.master.logcleaner.plugins";

   /*
    * Minimum percentage of free heap necessary for a successful cluster startup.
    */
  public static final float HBASE_CLUSTER_MINIMUM_MEMORY_THRESHOLD = 0.2f;

  public static final List<String> HBASE_NON_USER_TABLE_DIRS = new ArrayList<String>(
      Arrays.asList(new String[]{ HREGION_LOGDIR_NAME, HREGION_OLDLOGDIR_NAME,
          CORRUPT_DIR_NAME, Bytes.toString(META_TABLE_NAME),
          Bytes.toString(ROOT_TABLE_NAME), SPLIT_LOGDIR_NAME }));

  private HConstants() {
    // Can't be instantiated with this ctor.
  }
}
