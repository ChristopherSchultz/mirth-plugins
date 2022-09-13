# Mirth Channel Table Optimizer

This is a utility that will optimize the tables which support your Mirth
channels. It is not always necessary, and should only really be done if you
really understand what's going on with your Mirth tables.

Use of this utility ***will cause temporary downtime of your Mirth channel***. In
order to safely optimize your database tables, the channel must be _stopped_
and then restarted after the tables have been optimized.

Mirth tables for the following data will be optimized for each channel:

* Message metadata
* Message content
* Custom message metadata
* Message attachments
* Message statistics

On PostgreSQL databases, this executes a `VACUUM FULL` for each table.

On MySQL/MariaDB, this executes an `OPTIMIZE TABLE` for each table.

Please see your database vendor's documentation for these commands to see the
implications performing them.

## Configuration

This is a command-line utility which can take all configuration parameters as
command-line arguments. Because authentication is necessary for both the
database as well as Mirth's API, passwords are required. Passing passwords
on the command-line is not a secure practice. You can either use the `-P`
option to prompt-for-passwords or you can use the `-c` option to use a config
file which contains the authentication information.

The config file is a simple text-based configuration file containing 6 lines
of text: JDBC URL, JDBC username, JDBC password, API endpoint base, API
username, and API password. If you wish to prompt for passwords, leave
the associated lines _blank_ in the config file.

## Building

The Mirth Channel Table Optimizer can be built with Apache Maven.

   $ mvn package

This will compile this utility itself as well as bundle JDBC drivers for
supported databases into a single executable JAR file.

## Running

   $ java -jar channel-table-optimizer-_version_.jar -h

