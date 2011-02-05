/*
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

package org.apache.hadoop.hbase.security.rbac;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.hbase.util.Bytes;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;

/**
 * Represents an authorization for access for the given actions, optionally
 * restricted to the given column family, over the given table.  If the family
 * property is <code>null</code>, it implies full table access.
 */
public class TablePermission extends Permission {
  private static Log LOG = LogFactory.getLog(TablePermission.class);

  private byte[] table;
  private byte[] family;

  /** Nullary constructor for Writable, do not use */
  public TablePermission() {
    super();
  }

  /**
   * Constructor
   * @param table the table
   * @param family the family, can be null if a global permission on the table
   * @param assigned the list of allowed actions
   */
  public TablePermission(byte[] table, byte[] family, Action... assigned) {
    super(assigned);
    this.table = table;
    this.family = family;
  }

  /**
   * Constructor
   * @param table the table
   * @param family the family, can be null if a global permission on the table
   * @param actionCodes the list of allowed action codes
   */
  public TablePermission(byte[] table, byte[] family, byte[] actionCodes) {
    super(actionCodes);
    this.table = table;
    this.family = family;
  }

  public byte[] getTable() {
    return table;
  }

  public byte[] getFamily() {
    return family;
  }

  /**
   * Checks that a given table operation is authorized by this permission
   * instance.
   *
   * @param table
   * @param family
   * @param action
   * @return
   */
  public boolean implies(byte[] table, byte[] family, Action action) {
    if (!Bytes.equals(this.table, table)) {
      return false;
    }

    if (this.family != null &&
        (family == null ||
         !Bytes.equals(this.family, family))) {
      return false;
    }

    // check actions
    return super.implies(action);
  }

  public boolean equals(Object obj) {
    if (!(obj instanceof TablePermission)) {
      return false;
    }
    TablePermission other = (TablePermission)obj;

    if (!(Bytes.equals(table, other.getTable()) &&
        ((family == null && other.getFamily() == null) ||
         Bytes.equals(family, other.getFamily())
       ))) {
      return false;
    }

    // check actions
    return super.equals(other);
  }

  public String toString() {
    StringBuilder str = new StringBuilder("[TablePermission: ")
        .append("table=").append(Bytes.toString(table))
        .append(", family=").append(Bytes.toString(family))
        .append(", actions=");
    if (actions != null) {
      for (int i=0; i<actions.length; i++) {
        if (i > 0)
          str.append(",");
        if (actions[i] != null)
          str.append(actions[i].toString());
        else
          str.append("NULL");
      }
    }
    str.append("]");

    return str.toString();
  }

  @Override
  public void readFields(DataInput in) throws IOException {
    super.readFields(in);
    table = Bytes.readByteArray(in);
    if (in.readBoolean()) {
      family = Bytes.readByteArray(in);
    }
  }

  @Override
  public void write(DataOutput out) throws IOException {
    super.write(out);
    Bytes.writeByteArray(out, table);
    out.writeBoolean(family != null);
    if (family != null) {
      Bytes.writeByteArray(out, family);
    }
  }
}