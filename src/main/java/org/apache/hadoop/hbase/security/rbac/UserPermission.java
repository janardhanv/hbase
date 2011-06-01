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
 * Represents an authorization for access for the given table, column family
 * plus qualifier, over the given user.
 * It's more for display purpose.
 */
public class UserPermission extends TablePermission {
  private static Log LOG = LogFactory.getLog(UserPermission.class);

  private byte[] user;

  /** Nullary constructor for Writable, do not use */
  public UserPermission() {
    super();
  }

  /**
   * Constructor
   * @param user the user
   * @param table the table
   * @param family the family, can be null if a global permission on the user
   * @param assigned the list of allowed actions
   */
  public UserPermission(byte[] user, byte[] table, byte[] family,
                        Action... assigned) {
    super(table, family, assigned);
    this.user = user;
  }

  /**
   * Constructor
   * @param user the user
   * @param table the table
   * @param family the family, can be null if a global permission on the user
   * @param assigned the list of allowed actions
   */
  public UserPermission(byte[] user, byte[] table, byte[] family,
                        byte[] qualifier, Action... assigned) {
    super(table, family, qualifier, assigned);
    this.user = user;
  }

  /**
   * Constructor
   * @param user the user
   * @param family the family, can be null if a global permission on the user
   * @param actionCodes the list of allowed action codes
   */
  public UserPermission(byte[] user, byte[] table, byte[] family,
                        byte[] qualifier, byte[] actionCodes) {
    super(table, family, qualifier, actionCodes);
    this.user = user;
  }

  public byte[] getUser() {
    return user;
  }

  public boolean equals(Object obj) {
    if (!(obj instanceof UserPermission)) {
      return false;
    }
    UserPermission other = (UserPermission)obj;

    if ((Bytes.equals(user, other.getUser()) &&
        super.equals(obj))) {
      return true;
    } else {
      return false;
    }
  }

  public String toString() {
    StringBuilder str = new StringBuilder("UserPermission: ")
        .append("user=").append(Bytes.toString(user))
        .append(", ").append(super.toString());
    return str.toString();
  }

  @Override
  public void readFields(DataInput in) throws IOException {
    super.readFields(in);
    user = Bytes.readByteArray(in);
  }

  @Override
  public void write(DataOutput out) throws IOException {
    super.write(out);
    Bytes.writeByteArray(out, user);
  }
}
