# Introduction to sudo Remote Logging

Sudo can record detailed logs of privileged command execution, including
command metadata and terminal input/output (I/O logs).  These logs can be
stored locally on the system where sudo is executed, or transmitted to a
central log server for audit and compliance purposes.

sudo itself generates audit records as it executes the commands the user asked
for.  Depending on its configuration, it can write event and I/O logs to local
storage or stream them directly to a remote sudo_logsrvd, optionally
authenticated and encrypted using TLS. In a centralized logging deployment,
sudo acts as the client component and communicates directly with the remote
logging infrastructure while the command is running.

sudo_logsrvd is the server component of the sudo logging infrastructure. It
accepts connections from one or more sudo clients, receives event and I/O log
data, and stores the resulting sessions for later review. Centralizing logs on
a dedicated server simplifies auditing, reduces the risk of local log
tampering, and provides a single location from which recorded sessions can be
replayed using sudoreplay.

sudo_sendlog is a utility that transmits previously recorded local I/O logs to
a sudo_logsrvd instance. While it can be used as part of a workflow that
uploads locally stored logs, its primary purpose is testing, troubleshooting,
and maintenance. It is particularly useful for verifying connectivity,
validating TLS configuration, migrating historical logs, and debugging logging
deployments. In normal production operation, where sudo is configured for
remote logging, sudo_sendlog is typically not involved because sudo
communicates directly with sudo_logsrvd. `sudo_sendlog` is not required for
remote logging.


## Logging Architectures

### Local Logging

In the simplest deployment, sudo stores all logs locally.

```text
+--------+
|  sudo  |
+--------+
     |
     v
 Local I/O logs
```

This architecture requires no additional infrastructure but makes centralized
auditing more difficult.

### Centralized Real-Time Logging

The preferred architecture for production environments is direct communication
between sudo and a central log server.

```text
+--------+          +--------------+
|  sudo  |--------->| sudo_logsrvd |
+--------+          +--------------+
```

In this configuration, sudo sends event and I/O log data directly to
`sudo_logsrvd` while the command is running. The log server stores the received
sessions and makes them available for later replay and analysis.

Benefits include:

* Centralized audit trail
* Immediate log transmission: Reduced risk of local log tampering
* Small operational complexity
* no need to manage and upload local log archives
* Simplified compliance reporting
* Aggregation of logs from multiple hosts

For most installations, this is the recommended deployment model.


### Local Logging with Subsequent Upload

An alternative architecture stores logs locally first and uploads them later.

```text
+--------+
|  sudo  |
+--------+
     |
     v
 Local I/O logs
     |
     v
+--------------+
| sudo_sendlog |
+--------------+
     |
     v
+--------------+
| sudo_logsrvd |
+--------------+
```

This workflow may be useful when:

* Network connectivity is temporarily unavailable
* Existing local logs must be migrated to a central server
* Testing or troubleshooting a log server deployment

However, it should generally not be considered the primary production
architecture when direct remote logging is available.

## Session Replay

Logs stored by `sudo_logsrvd` can be replayed using `sudoreplay`, allowing
administrators and auditors to review a user's terminal session, including
command output and interactive input.

This provides a detailed audit trail that goes beyond traditional syslog-style
event logging.
