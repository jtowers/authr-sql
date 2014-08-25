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
        host: 'localhost',
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

## Config

If you are using fields outside of the [default user config](https://github.com/jtowers/authr#user-configuration), you must specify a `custom` key in your config that defines the names and data types for each extra field.

Example:

```
// Use the default error message and user values
var config = {
    db:{
        type:'mysql',
        host:'localhost',
        port: 3306,
        database_name: 'authr',
        collection: 'users'
    },
    // Specify custom fields
    custom:{
        company_name: {type: 'string'}
    }
}
```

This setup will specify a SQL database that uses the default column names for the user information (e.g., username and password) and an extra field for company name.

authr-sql doesn't currently set default values for existing columns, so if you have a schema in your database already, make sure it is set to handle null values or you will get errors.

Some sort of validation may be added in the future to prevent those.
