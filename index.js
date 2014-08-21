/** @module authr-nedb */

var Sequelize = require('sequelize');
var moment = require('moment');
var bcrypt = require('bcrypt');
var crypto = require('crypto');

/**
 * Represents a new Adapter instance for authr-sql.
 * @class
 * @param {object} config - Authr config object
 */

function Adapter(config) {
  this.config = config;
  sqlconfig = {
    port: config.db.port,
    dialect: config.db.type,
    storage: confg.db.name
  };

  this.db = new Sequelize(config.db.database_name, config.db.username, config.db.password, sqlconfig);
  this.buildUserModel();
}

/**
 * Function used to build user model
 * @function
 * @name buildUserModel
 */
this.Adapter.prototype.buildUserModel = function () {
  var self = this;
  var config = {
    _id: {
      type: Sequelize.INTEGER,
      autoIncrement: true,
      primaryKey: true
    }
  };
  for(var key in this.config.user) {
    switch(key) {
    case 'username':
      config[this.config.user.username] = Sequelize.STRING;
      break;
    case 'password':
      config[this.config.user.password] = Sequelize.STRING;
      break;
    case 'account_locked':
      config[this.config.user.account_locked] = Sequelize.BOOLEAN;
      break;
    case 'account_locked_until':
      config[this.config.user.account_locked_until] = Sequelize.DATE;
      break;
    case 'account_failed_attempts':
      config[this.config.user.account_failed_attempts] = Sequelize.INTEGER;
      break;
    case 'account_last_failed_attempt':
      config[this.config.user.account_last_failed_attempt] = Sequelize.DATE;
      break;
    case 'email_address':
      if(this.config.user.email_address !== this.config.user.username) {
        config[this.config.user.email_address] = Sequelize.STRING;
      }
      break;
    case 'email_verified':
      if(this.config.security.email_verification) {
        config[this.user.email_verified] = Sequelize.STRING;
      }
      break;
    case 'email_verification_hash':
      if(this.config.security.email_verification) {
        config[this.user.email_verification_hash] = Sequelize.STRING;
      }
      break;
    case 'email_verification_hash_expires':
      if(this.config.security.email_verification) {
        config[this.user.email_verification_hash_expires] = Sequelize.DATE;
      }
      break;
    case 'password_reset_token':
      config[this.user.password_reset_token] = Sequelize.STRING;
      break;
    case 'password_reset_token_expiration':
      config[this.user.password_reset_token_expiration] = Sequelize.STRING;
      break;
    }
  }

  this.User = Sequelize.define('User', config, {
    table_name: this.config.db.collection,
    timestamps: false
  });

  this.User.Sequelize.sync({}).error(function (err) {
    throw err;
  });
};

/**
 * Passes the signup object to the adapter so the adapter utilities can access them
 * @function
 * @name signupConfig
 * @param {Object} - User object to be persisted to the database
 * @example
 * adapter.signUpConfig({account: {username: 'some_user', password: 'some_password'}});
 */
Adapter.prototype.signupConfig = function (signup) {
  this.signup = signup;
};

/**
 * Check to make sure the credentials were supplied
 * @function
 * @name checkCredentials
 * @return {null|String}
 */
Adapter.prototype.checkCredentials = function () {
  username = this.signup[this.config.user.username];
  password = this.signup[this.config.user.password];
  if(!username || !password) {
    return this.config.errmsg.un_and_pw_required;
  } else {
    return null;
  }
};

/**
 * Check to see if the username is taken
 * @function
 * @name isUsernameTaken
 * @param {Object} object - object to query
 * @path {Object}  path - path to the value
 * @param {Function} cb - Run callback when finished connecting
 * @return {Function}
 */
Adapter.prototype.isValueTaken = function (object, path, cb) {
  var self = this;
  var val = object[path];
  if(val) {
    val.toLowerCase();
  }
  var query = {};
  query[path] = val;
  this.db.findOne({
    where: query
  }).success(function (user) {
    if(user) {
      self.user = user;
      return cb(true);
    } else {
      return cb(false);
    }
  }).error(function (err) {
    if(err) throw err;
  });
};

/**
 * Hashes the password using bcrypt and the settings specified in the authr config
 * @function
 * @name hash_password
 * @param {Callback} callback - run a callback when hashing is complete
 * @return {Callback}
 */
Adapter.prototype.hash_password = function (callback) {
  var password = this.signup[this.config.user.password];
  var self = this;
  bcrypt.genSalt(this.config.security.hash_salt_factor, function (err, salt) {
    if(err) {
      throw err;
    } else {
      bcrypt.hash(password, salt, function (err, hash) {
        if(err) {
          throw err;
        } else {
          self.signup[self.config.user.password] = hash;
          callback(err, hash);
        }
      });
    }
  });
};

/**
 * Create account security defaults
 * @function
 * @name doEmailVerification
 * @param {Object} obj - object to add to
 */
Adapter.prototype.buildAccountSecurity = function (obj) {
  obj[this.config.user.account_locked] = false;
  obj[this.config.user.account_locked_until] = null;
  obj[this.config.user.account_failed_attempts] = 0;
  obj[this.config.user.account_last_failed_attempt] = null;
};

/**
 * Create email verification code using the username and current datetime.
 * Sets expiration to now + number of hours defined in authr config (config.security.email_verification_expiration_hours)
 * @function
 * @name doEmailVerification
 * @param {Object} obj - Object to modify
 * @param {Callback} callback - Run a callback when finished
 * @return {Callback}
 */
Adapter.prototype.doEmailVerification = function (obj, callback) {
  var self = this;
  this.generateToken(20, function (err, token) {
    if(err) throw err;
    obj[self.config.user.email_verification_hash]= token;
    obj[self.config.user.email_verification_hash_expires] = moment().add(self.config.security.email_verification_expiration_hours, 'hours').toDate();
    obj[self.config.user.email_verified] = false;
    return callback(null, obj);
  });

};

/**
 * Saves the user saved in this.signup. Callback returns any errors and the user, if successfully inserted
 * @function
 * @name saveUser
 * @param {Callback} callback - Run a callback after the user has been inserted
 * @return {Callback}
 */
Adapter.prototype.saveUser = function (callback) {
  var user = this.User.create(this.signup).success(function(user){
    callback(null, user);
  }).error(function(err){
    if(err) throw err;
  });
};