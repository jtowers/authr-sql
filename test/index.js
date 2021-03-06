var should = require('chai').should();
var blanket = require('blanket');
var Adapter = require('../index.js');
var moment = require('moment');
process.setMaxListeners(50);
describe('constructor', function () {

    describe('db operations', function () {
        var adapter;
        var signup_config;
        var authr_config;
        beforeEach(function (done) {
            authr_config = {
                user: {
                    username: 'username',
                    password: 'password',
                    password_reset_token: 'password_reset_token',
                    password_reset_token_expiration: 'password_reset_token_expiration',
                    account_locked: 'account_locked',
                    account_locked_until: 'account_locked_until',
                    account_failed_attempts: 'account_failed_attempts',
                    account_last_failed_attempt: 'account_last_failed_attempt',
                    email_address: 'username',
                    email_verified: 'email_verified',
                    email_verification_hash: 'email_verification_hash',
                    email_verification_hash_expires: 'email_verification_expires'
                },
                db: {
                    type: 'sqlite',
                    host: '127.0.0.1',
                    port: '3306',
                    username: 'root',
                    password: '',
                    database_name: 'authr',
                    collection: 'users'
                },
                security: {
                    hash_password: true,
                    hash_salt_factor: 1, // salt work factor reduced for testing
                    max_failed_login_attempts: 10,
                    reset_attempts_after_minutes: 5,
                    lock_account_for_minutes: 30,
                    email_verification: true,
                    email_verification_expiration_hours: 12
                },
                errmsg: {
                    username_taken: 'This username is taken Please choose another.',
                    token_not_found: 'This signup token does not exist. Please try again.',
                    token_expired: 'This token has expired. A new one has been generated.',
                    un_and_pw_required: 'A username and password are required to log in.',
                    username_not_found: 'Username not found. Please try again or sign up.',
                    password_incorrect: 'Password incorrect. Your account will be locked after ##i## more failed attempts.',
                    account_locked: 'Too many failed attempts. This account will be locked for ##i## minutes.'
                },
                custom: {
                    test_noschema: {
                        type: 'string'
                    }
                }

            };

            signup_config = {

                username: 'test@test.com',
                password: 'test',
                test_noschema: 'test_value'

            };
            adapter = new Adapter(authr_config, function () {
                done();
            });

        });
        
        describe('', function(){
            it('should have the right db config', function (done) {
        adapter.config.db.type.should.equal('sqlite');
        done();
    });

    it('should be able to connect to database', function (done) {
        adapter.connect(function (err) {
            should.not.exist(err);
            done();
        });
    });

    it('should have a database object', function (done) {
        adapter.connect(function (err) {
            should.exist(adapter.db);
            done();
        });
    });
        });

        describe('', function () {
            var saved_user;
            beforeEach(function (done) {
                user = {
                    username: 'test@test.com',
                    password: 'test',
                    test_noschema: 'test_value'

                };
                adapter.connect(function (err) {
                    if(err) {
                        throw err;
                    } else {
                        adapter.doEmailVerification(user, function (err, user) {
                            adapter.saveUser(user, function (err, user) {
                                saved_user = user;
                                done();
                            });
                        });

                    }
                });
            });

            afterEach(function (done) {
                adapter.resetCollection(function (err) {
                    done();
                });
            });
            it('should be able to find users', function (done) {
                adapter.isValueTaken(saved_user, adapter.config.user.username, function (err, user) {
                    should.exist(user);
                    user.values.username.should.equal(saved_user.username);
                    done();
                });
            });

            it('should be able to get users by email address', function (done) {
                adapter.getUserByEmail(saved_user[adapter.config.user.email_address], function (err, user) {
                    should.exist(user);
                    user.values.username.should.equal(saved_user.username);
                    done();
                });
            });

            it('should be able to get users by username', function (done) {
                adapter.getUserByUsername(saved_user[adapter.config.user.username], function (err, user) {
                    should.exist(user);
                    user.values.username.should.equal(saved_user.username);
                    done();
                });
            });
            it('should be able to increment failed logins', function (done) {
                adapter.isValueTaken(saved_user, adapter.config.user.username, function (err, user) {
                    adapter.incrementFailedLogins(user, function (err, user) {
                        should.exist(err);
                    });
                    done();
                });
            });
            it('should be able to lock a user\'s account', function (done) {
                adapter.isValueTaken(saved_user, adapter.config.user.username, function (err, user) {
                    adapter.lockUserAccount(user, function (err, user) {
                        should.exist(err);
                        user.account_locked.should.equal(true);
                    });
                    done();
                });
            });
            it('should be able to unlock a user\'s account', function (done) {
                adapter.isValueTaken(saved_user, adapter.config.user.username, function (err, user) {
                    user.account_locked = true;
                    user.account_locked_until = moment().toDate();
                    adapter.unlockUserAccount(user, function (err, user) {
                        should.not.exist(err);
                        user.account_locked.should.equal(false);
                        done();
                    });
                });
            });
            it('should be able to determine if a user\'s account is locked', function (done) {
                adapter.isValueTaken(saved_user, adapter.config.user.username, function (err, user) {
                    adapter.isAccountLocked(user, function (err, isLocked) {
                        should.not.exist(err);
                        isLocked.should.equal(false);
                        done();
                    });
                });
            });
            it('should be able to build account security', function (done) {
                var obj = {};
                obj = adapter.buildAccountSecurity(obj);
                obj.account_locked.should.equal(false);
                done();
            });
            it('should be able to check credentials', function (done) {
                var obj = {
                    username: 'something',
                    password: 'something_else'
                };
                adapter.checkCredentials(obj, function (err, obj) {
                    should.not.exist(err);
                    should.exist(obj);
                    done();
                });
            });
            it('should give an error when passwords are wrong', function (done) {
                var user = {
                    username: 'test@test.com',
                    password: 'test2'
                };
                adapter.isValueTaken(saved_user, adapter.config.user.username, function (err, usr) {
                    adapter.comparePassword(usr, user, function (err, user) {
                        should.exist(err);
                        done();
                    });
                });
            });
            it('should be able to delete a user', function (done) {
                adapter.isValueTaken(saved_user, adapter.config.user.username, function (err, user) {
                    adapter.deleteAccount(user, function (err, user) {
                        should.not.exist(err);
                        adapter.isValueTaken(saved_user, adapter.config.user.username, function (err, user) {
                            should.not.exist(user);
                            done();
                        });
                    });

                });
            });
            it('should be able to generate a signup token', function (done) {
                var obj = {};
                adapter.doEmailVerification(obj, function (err, object) {
                    should.not.exist(err);
                    should.exist(object);
                    should.exist(object[adapter.config.user.email_verification_hash]);
                    should.exist(object[adapter.config.user.email_verification_hash_expires]);
                    should.exist(object[adapter.config.user.email_verified]);
                    object[adapter.config.user.email_verified].should.equal(false);
                    done();
                });
            });
            it('should be able check to see if a signup token is expired', function (done) {
                adapter.isValueTaken(saved_user, adapter.config.user.username, function (err, user) {
                    var isExpired = adapter.emailVerificationExpired(user);
                    isExpired.should.equal(false);
                    done();
                });
            });

            it('should be able to expire failed login attempts', function (done) {
                adapter.isValueTaken(saved_user, adapter.config.user.username, function (err, user) {
                    user.account_failed_attempts = 5;
                    user.account_last_failed_attempt = moment().add(-10, 'minutes');
                    adapter.failedAttemptsExpired(user, function (err, expired) {
                        should.not.exist(err);
                        user.account_failed_attempts.should.equal(0);
                        expired.should.equal(true);
                        done();
                    });
                });
            });
            it('should be able to hash a new account\'s password', function (done) {
                auser = {
                    username: 'test@test.com',
                    password: 'test'

                };
                adapter.hashPassword(user, user, 'password', function (err, usr) {
                    should.not.exist(err);
                    usr.password.should.not.equal('test');
                    done();
                });
            });
            it('should be able to hash an existing user\'s password', function (done) {
                var password = {
                    password: 'test2'
                };
                adapter.isValueTaken(saved_user, adapter.config.user.username, function (err, user) {
                    adapter.hashPassword(password, user, 'password', function (err, user) {
                        should.not.exist(err);
                        saved_user.password.should.not.equal(user.password);
                        done();
                    });
                });
            });
            it('should be able to set a new password', function (done) {
                adapter.isValueTaken(saved_user, adapter.config.user.username, function (err, user) {
                    user[adapter.config.user.password] = 'new_password';
                    adapter.resetPassword(user, function (err, usr) {
                        usr[adapter.config.user.password].should.equal('new_password');
                        done();
                    });
                });
            });

            it('should be able to check to see if a password reset token is expired', function (done) {
                adapter.isValueTaken(saved_user, adapter.config.user.username, function (err, user) {
                    user[adapter.config.user.password_reset_token_expiration] = moment().add(-1, 'hours').toDate();
                    var isExpired = adapter.resetTokenExpired(user);
                    isExpired.should.equal(true);
                    done();
                });
            });
            it('should be able to save a password rest token', function(done){
                adapter.isValueTaken(saved_user, adapter.config.user.username, function(err, user){
                   var token = 'some_token';
                    adapter.savePWResetToken(user, token, function(err, usr){
                        should.not.exist(err);
                        should.exist(usr);
                        usr[adapter.config.user.password_reset_token].should.equal(token);
                        done();
                    });
                });
            });

            it('should be able to verify a user email address', function(done){
                adapter.isValueTaken(saved_user, adapter.config.user.username, function(err, user){
                    adapter.verifyEmailAddress(user, function(err, usr){
                        should.not.exist(err);
                        usr[adapter.config.user.email_verified].should.equal(true);
                        done();
                    });
                });
            });
        });
    });
});