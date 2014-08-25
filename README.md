authr-sql
=========

## Introduction
This is a SQL adapter for authr.

It uses Sequelize and supports the following databases:

- MySQL
- MariaDB
- PostgresSQL
- SQLite

## Installation
Use this adapter with authr and the database engine of your choice:

1. Install authr, authr-sql, and a database engine
`npm install -save authr authr-sql mysql`

2. Set up authr

```
var Authr = require('authr');

// create a config object and create a new instance of authr with it
var config = {
    db: {
        type: 'mysql',
        host: localhost,
        port: 3306,
        database_name: 'authr',
        collection: 'users'
    }
}

var authr = new Authr(config);

var signup = {
    username: 'some_user',
    password: 'super_secure'
}

authr.signUp(signup, function(user){
    console.log(user); // returns the user inserted into nedb.
});
```
