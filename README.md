# cassandra secure plugin
#####
Cassandra security authentication plug-in based on SCRAM-SHA256 algorithm.

see https://tools.ietf.org/html/rfc5802

## Compile
`
 mvn clean package
`

## Server

Put cassandra-secure-plugin-1.x.x.jar to $CASSANDRA_HOME/lib

Modify cassandra.yaml:  
```
authenticator: com.zhaoyanblog.cassandra.server.ScramAuthenticator  
authorizer: CassandraAuthorizer  
role_manager: com.zhaoyanblog.cassandra.server.ScramRoleManager
```

## Client

You can install it in your application using the following Maven dependency

```
<groupId>com.zhaoyanblog</groupId>  
<artifactId>cassandra-secure-plugin</artifactId>  
<version>1.0.0</version>
```
Build Cluster with cassandra java-driver like this:

```
Cluster cluster = Cluster.builder()  
        .addContactPoint("127.0.0.1")  
        .withAuthProvider(new ScramAuthProvider("your username","your password"))  
        .build();  
Session session = cluster.connect();
```
# License
Copyright 2018, zhaoyanblog.com

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
