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

function Adapter(config, callback) {
    var self = this;
    this.config = config;
    sqlconfig = {
        port: config.db.port,
        dialect: config.db.type,
        storage: config.db.name,
        logging: false
    };
    this.db = new Sequelize(config.db.database_name, config.db.username, config.db.password, sqlconfig);
    this.connect(function (err) {
        self.buildUserModel(function () {
            callback();
        });
    });
}

Adapter.prototype.connect = function (callback) {
    this.db.authenticate().complete(function (err) {
        callback(err);
    });
};

/**
 * Function used to build user model
 * @function
 * @name buildUserModel
 */
Adapter.prototype.buildUserModel = function (callback) {
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
                config[this.config.user.email_verified] = Sequelize.STRING;
            }
            break;
        case 'email_verification_hash':
            if(this.config.security.email_verification) {
                config[this.config.user.email_verification_hash] = Sequelize.STRING;
            }
            break;
        case 'email_verification_hash_expires':
            if(this.config.security.email_verification) {
                config[this.config.user.email_verification_hash_expires] = Sequelize.DATE;
            }
            break;
        case 'password_reset_token':
            config[this.config.user.password_reset_token] = Sequelize.STRING;
            break;
        case 'password_reset_token_expiration':
            config[this.config.user.password_reset_token_expiration] = Sequelize.STRING;
            break;
        }
    }

    for(var key in this.config.custom){
        var custom = this.config.custom;
        var type = custom[key]['type'];
        switch(type){
            case 'string':
                config[key] = Sequelize.STRING;
                break;
            case 'string.binary':
                config[key] = Sequelize.STRING.BINARY;
                break;
            case 'text':
                config[key] = Sequelize.TEXT;
                break;
            case 'integer':
                config[key] = Sequelize.INTEGER;
                break;
            case 'bigint':
                config[key] = Sequelize.BIGINT;
                break;
            case 'float':
                config[key] = Sequelize.FLOAT;
                break;
            case 'decimal':
                config[key] = Sequelize.DECIMAL;
                break;
            case 'date':
                config[key] = Sequelize.DATE;
                break;
            case 'boolean':
                config[key] = Sequelize.BOOLEAN;
                break;
            default:
                config[key] = Sequelize.STRING;
        }
    }
    this.User = this.db.define('User', config, {
        table_name: this.config.db.collection,
        timestamps: false
    });
    this.User.sync({}).success(function () {
        callback();
    }).error(function (err) {
        throw err;
    });

};

// PUBLIC API METHODS
// ------------------

/**
 * Create account security defaults
 * @param {Object} obj - object to add to
 * @return {Object} obj - object containing accoutn security settings
 */
Adapter.prototype.buildAccountSecurity = function (obj) {
    obj[this.config.user.account_locked] = false;
    obj[this.config.user.account_locked_until] = null;
    obj[this.config.user.account_failed_attempts] = 0;
    obj[this.config.user.acount_last_failed_attempt] = null;
    return obj;
};

/**
 * Check to make sure the credentials were supplied
 * @param {Object} obj - Object containing credentials to check
 * @param {checkCredentialsCallback} callback - Callback to run after finished checking credentials
 */
Adapter.prototype.checkCredentials = function (obj, callback) {
    username = obj[this.config.user.username];
    password = obj[this.config.user.password];

    if(!username || !password) {
        return callback(this.config.errmsg.un_and_pw_required, obj);
    } else {
        return callback(null, obj);
    }
};

/**
 * Compare the supplied password with the stored hashed password
 * @param {Object} user - original user object
 * @pram {Object} login - login object containing the password to test
 * @param {comparePasswordCallback} callback - execute callback after the comparison
 */
Adapter.prototype.comparePassword = function (user, login, callback) {
    var self = this;
    var db_pass = user[this.config.user.password];
    var supplied_pass = login[this.config.user.password];
    if(this.config.security.hash_password) {
        bcrypt.compare(supplied_pass, db_pass, function (err, match) {
            if(match) {
                return callback(null, user);
            } else {
                if(self.config.security.max_failed_login_attempts) {
                    self.incrementFailedLogins(user, function (err) {
                        return callback(err, user);
                    });
                } else {
                    return callback(self.config.errmsg.password_incorrect);
                }
            }
        });
    } else {

        if(db_pass === supplied_pass) {
            return callback(null, user);
        } else {
            if(self.config.security.max_failed_login_attempts) {
                this.incrementFailedLogins(user, function (err) {
                    return callback(err, user);
                });
            } else {
                return callback(self.config.errmsg.password_incorrect, user);
            }
        }
    }

};

/**
 * Find an account by email address
 * @param {string} email - email address to look for
 * @param {getUserByEmailCallback} callback - callback to execute when finished
 * @return {Callback}
 */
Adapter.prototype.getUserByEmail = function (email, callback) {
    var self = this;
    var query = {};
    query[this.config.user.email_address] = email;
    this.User.find({
        where: query
    }).success(function (user) {
        if(user) {
            return callback(null, user);
        } else {
            return callback(self.config.errmsg.username_not_found, null);
        }
    }).error(function (err) {
        throw err;
    });
};

/**
 * Handles response for getUserByEmail method
 * @callback getUserByEmailCallback
 * @param {String} err - error message, if it exists
 * @param {Object} user - user found by query
 */

/**
 * Find an account by username
 * @param {string} username - username or email address to look for
 * @param {getUserByUsernameCallback} callback - callback to execute when finished
 */
Adapter.prototype.getUserByUsername = function (username, callback) {
    var self = this;
    var query = {};
    query[this.config.user.email_address] = username;

    this.User.find({
        where: query
    }).success(function (user) {
        if(user) {
            return callback(null, user);
        } else {
            return callback(self.config.errmsg.username_not_found, null);
        }
    }).error(function (err) {
        throw err;
    });

};

/**
 * Check to see if a value exists in the database. Supply the source object and the path to the value to be checked
 * @param {Object} object - object to query
 * @path {Object}  path - path to the value
 * @param {isValueTakenCallback} callback - Run a callback after checking the database
 */
Adapter.prototype.isValueTaken = function (object, path, callback) {
    var self = this;
    var val = object[path];
    if(val) {
        val = val.toLowerCase();
    }
    var query = {};
    query[path] = val;
    this.User.find({
        where: query
    }).success(function (user) {
        callback(null, user);
    }).error(function (err) {
        throw err;
    });
};

/**
 * Handles response for isValueTaken method
 * @callback isValueTakenCallback
 * @param {String} err - error message, if any
 * @param {Boolean|Object} doc - Document, if found, or false if not found
 */

/**
 * Delete a user account
 * @param {Object} user - object containing user to delete
 * @param {deleteAccountCallback} callback - callback to run when finished
 */
Adapter.prototype.deleteAccount = function (user, callback) {
    var self = this;
    var username = user[this.config.user.username];
    var query = {};
    query[this.config.user.username] = username;
    user.destroy().success(function () {
        callback(null, user);
    }).error(function (err) {
        throw err;
    });
};

/**
 * Handles response for deleteAccount method
 * @callback deleteAccountCallback
 * @param {String} err - error message, if it exists
 * @param {Object} user - user that was deleted
 */

/**
 * Create email verification code using the username and current datetime.
 * Sets expiration to now + number of hours defined in authr config (config.security.email_verification_expiration_hours)
 * @param {Object} obj - Object to modify
 * @param {doEmailVerificationCallback} callback - Run a callback when finished
 */
Adapter.prototype.doEmailVerification = function (obj, callback) {
    var self = this;
    this.generateToken(20, function (err, token) {
        if(err) {
            return callback(err, null);
        } else {
            obj[self.config.user.email_verification_hash] = token;
            obj[self.config.user.email_verification_hash_expires] = moment().add(self.config.security.email_verification_expiration_hours, 'hours').toDate();
            obj[self.config.user.email_verified] = false;
            return callback(null, obj);
        }
    });

};

/**
 * Handles response for doEmailVerification method
 * @callback doEmailVerificationCallback
 * @param {String} err - error message, if it exists
 * @param {Object} obj - object passed in, plus the verification token and expiration
 */

/**
 * Check to see if the signup token is expired
 * @return {Boolean}
 */
Adapter.prototype.emailVerificationExpired = function (user) {
  var now = moment();
    expr = user[this.config.user.email_verification_hash_expires];
  var expires = moment(expr);
  if(now.isAfter(expires)) {
    return true;
  } else {
    return false;
  }
};

/**
 * Checks to see if the user's failed attempts are expired and resets them if they are.
 * @param {Object} user - user to check
 * @param {failedAttemptsExpiredCallback} callback - execute a callback when the function is finished
 * @return {Callback}
 */
Adapter.prototype.failedAttemptsExpired = function (user, callback) {
    var now = moment();
    var last_failed_attempt = user[this.config.user.account_last_failed_attempt];
    var attempts_expire = moment(last_failed_attempt).add(this.config.security.reset_attempts_after_minutes, 'minutes');
    if(now.isAfter(attempts_expire)) {
        this.resetFailedLoginAttempts(user, function () {
            callback(null, true);
        });
    } else {
        return callback(null, false);
    }
};

/**
 * Handles response for failedAttemptsExpired method
 * @callback failedAttemptsExpiredCallback
 * @param {String} err - error message, if any
 * @param {Boolean} expired - Returns true if the attempts were expired, false if not
 */


/**
 * Looks for user account using password reset token
 * @param {String} token - reset token to look for
 * @param {findResetTokenCallback} callback - execute callback when account is found
 * @return {Callback}
 */
Adapter.prototype.findResetToken = function (token, callback) {
    var self = this;
    var query = {};
    query[this.config.user.password_reset_token] = token;
    this.User.find({where:query}).success(function(user){
        if(user){
            callback(null, user);
        } else {
            callback(self.config.errmsg.token_not_found);
        }
    }).error(function(err){
        throw err;
    });
};

/**
 * Handles response for findResetToken method
 * @callback findResetTokenCallback
 * @param {String} err - error message, if it exists
 * @param {Object} user - user associated with reset token
 */

/**
 * Looks for user account using email verification token
 * @param {String} token - verification token to look for
 * @param {findVerificationTokenCallback} callback - execute callback when account is found
 */
Adapter.prototype.findVerificationToken = function (token, callback) {
    var self = this;
    var query = {};
    query[this.config.user.email_verification_hash] = token;
    this.User.find({where:query}).success(function(user){
        if(user){
            callback(null, user);
        } else {
            callback(self.config.errmsg.token_not_found, null);
        }
    }).error(function(err){
        throw err;
    });
};

/**
 * Handles response for findVerificationToken method
 * @callback findVerificationTokenCallback
 * @param {String} err - error message, if it exists
 * @param {Object} user - user associated with the token
 */

/**
 * Hashes a password using a path in a given object as the value
 * @param {Object} source_object - object to pull the password from
 * @param {Object} dest_object - object to save the password to
 * @param {String} path - path to the password field
 * @param {hashPasswordCallback} callback - return error and/or object with hashed password when finished
 */
Adapter.prototype.hashPassword = function (source_object, dest_object, path, callback) {
    var password = source_object[path];
    var self = this;
    bcrypt.genSalt(this.config.security.hash_salt_factor, function (err, salt) {
        if(err) {
            return callback(err, null);
        } else {
            bcrypt.hash(password, salt, function (err, hash) {
                if(err) {
                    return callback(err, null);
                } else {
                    dest_object[path] = hash;
                    return callback(err, dest_object);
                }
            });
        }
    });
};

/**
 * Handles response for hashPassword method
 * @callback hashPasswordCallback
 * @param {String} err - error message, if any
 * @param {Object} dest_object - Returns the object passed to the function with the hashed password in place of the plain-text password
 */



/**
 * Check to see if the account is locked.
 * First checks to see if there is a lock. If there is, checks to see if the lock has expired.
 * @param {Object} user - user object to check
 * @param {isAccountLockedCallback} callback - execute a callback after finished checking lock status
 */
Adapter.prototype.isAccountLocked = function (user, callback) {
    var isLocked = user[this.config.user.account_locked];
    var unlocked_at;
    if(isLocked) {
        unlocked_at = user[this.config.user.account_locked_until];
        var now = moment();
        var expires = moment(unlocked_at);
        if(now.isAfter(expires)) {
            this.unlockUserAccount(user, function () {
                return callback(null, false);
            });
        } else {
            return callback({
                err: this.config.errmsg.account_locked,
                unlocked_at: unlocked_at
            });
        }
    } else {
        return callback(null, false);
    }

};

/**
 * Handles response for isAccountLocked method
 * @callback isAccountLockedCallback
 * @param {String} err - error message, if any
 * @param {Boolean} isLocked - True if the account is locked, false if not
 */

// UTILITY METHODS
// ---------------

/**
 * Reset failed login attempts
 * @function
 * @private
 * @name resetFailedLoginAttempts
 * @param {Object} user - user to reset expired login attempts for
 * @param {Callback} - execute a callback after the attempts are reset
 */
Adapter.prototype.resetFailedLoginAttempts = function (user, callback) {
    user[this.config.user.account_failed_attempts] = 0;
    user.save().success(function(){
        return callback(null, user);
    }).error(function(err){
        throw err;
    });
};

/**
 * Called after a failed login attempt. Either increment the number of failed login attempts and report the error or lock the account and report that.
 * @function
 * @private
 * @name incrementFailedLogins
 * @param {Object} user - user to increment logins for
 * @param {Callback} callback - execute a callback after the function runs
 * @return {Callback}
 */
Adapter.prototype.incrementFailedLogins = function (user, callback) {
    var current_failed_logins = user[this.config.user.account_failed_attempts] + 1;
    var max_failed_attempts = this.config.security.max_failed_login_attempts;
    var query;
    var msg;
    var self = this;
    if(current_failed_logins >= max_failed_attempts) {
        this.lockUserAccount(user, function (err, user) {
            return callback(err, user);
        });
    } else {
        user[this.config.user.account_failed_attempts] = current_failed_logins;
        user[this.config.user.account_last_failed_attempt] = moment().toDate();
        msg = this.config.errmsg.password_incorrect.replace('##i##', max_failed_attempts - current_failed_logins);
        errmsg = {
            err: msg,
            remaining_attempts: max_failed_attempts - current_failed_logins
        };
        query = {};
        query[this.config.user.username] = user[this.config.user.username];
        user.save().success(function () {
            return callback(errmsg, user.values);
        }).error(function (err) {
            throw err;
        });
    }
};

/**
 * Lock a user's account after specified number of login attempts
 * @function
 * @private
 * @name lockUserAccount
 * @param {Object} user - user account to lock
 * @param {Callback} callback - execute a callback after the lock
 */
Adapter.prototype.lockUserAccount = function (user, callback) {
    var expires;
    var query;
    var errmsg = this.config.errmsg.account_locked.replace('##i##', this.config.security.lock_account_for_minutes);
    var self = this;
    expires = moment().add(this.config.security.lock_account_for_minutes, 'minutes');
    user[this.config.user.account_locked] = true;
    user[this.config.user.account_locked_until] = expires.toDate();
    user.save().success(function () {
        errobj = {
            err: errmsg,
            lock_until: expires.toDate()
        };
        return callback(errobj, user);
    }).error(function (err) {
        throw err;
    });
};

/**
 * Handles response for doEmailVerification method
 * @callback doEmailVerificationCallback
 * @param {String} err - error message, if it exists
 * @param {Object} obj - object passed in, plus the verification token and expiration
 */

/**
 * Generate a signup or password reset token using node crypto
 * @param size - size
 * @param {generateTokenCallback} callback - execute a callback after the token is generated
 */
Adapter.prototype.generateToken = function (size, callback) {
    crypto.randomBytes(size, function (err, buf) {
        if(err) throw err;
        var token = buf.toString('hex');
        callback(err, token);
    });
};

/**
 * Handles response for generateToken method
 * @callback generateTokenCallback
 * @param {String} err - error message, if it exists
 * @param {Object} obj - generated token
 */


/**
 * Reset failed login attempts
 * @function
 * @private
 * @name resetFailedLoginAttempts
 * @param {Object} user - user to reset expired login attempts for
 * @param {Callback} - execute a callback after the attempts are reset
 */
Adapter.prototype.resetFailedLoginAttempts = function (user, callback) {
    user[this.config.user.account_failed_attempts] = 0;

  user.save().success(function() {
    callback(user);
  }).error(function(err){
      throw err;
  });
};

/**
 * Unlock a user's account (e.g., if the lock has expired)
 * @function
 * @private
 * @name unlockUserAccount
 * @param {Callback} user - user to unlock
 * @param {Callback} callback - execute a callback after the account is unlocked.
 */
Adapter.prototype.unlockUserAccount = function (user, callback) {
    user[this.config.user.account_locked] = false;
    user[this.config.user.account_locked_until] = null;
    
    user.save().success(function(){
        return callback(null, user);
    }).error(function(err){
        throw err;
    });

};

/**
 * Saves the user saved in this.signup. Callback returns any errors and the user, if successfully inserted
 * @function
 * @name saveUser
 * @param {Callback} callback - Run a callback after the user has been inserted
 * @return {Callback}
 */
Adapter.prototype.saveUser = function (user, callback) {
    var save_me = this.User.build(user);
    save_me.save().success(function (user) {
        callback(null, user.values);
    }).error(function (err) {
        throw err;
    });
};

/**
 * Remove the collection. Mostly used for testing. Will probably find a use for it.
 * @function
 * @private
 * @name resetCollection
 * @param {Callback} callback - Execute callback when finished dropping the collection
 * @return {Callback}
 */
Adapter.prototype.resetCollection = function (callback) {
    this.db.query('DELETE FROM `Users`').success(function () {
        callback();
    }).error(function (err) {
        throw err;
    });
};

module.exports = Adapter;