var loopback = require('loopback');
var path = require('path');
var SALT_WORK_FACTOR = 10;
var crypto = require('crypto');
var debug = require('debug')('loopback:stormpath-user');
var assert = require('assert');

var bcrypt;
try {
  // Try the native module first
  bcrypt = require('bcrypt');
  // Browserify returns an empty object
  if (bcrypt && typeof bcrypt.compare !== 'function') {
    bcrypt = require('bcryptjs');
  }
} catch (err) {
  // Fall back to pure JS impl
  bcrypt = require('bcryptjs');
}

var DEFAULT_TTL = 1209600; // 2 weeks in seconds
var DEFAULT_RESET_PW_TTL = 15 * 60; // 15 mins in seconds
var DEFAULT_MAX_TTL = 31556926; // 1 year in seconds

/**
 * Stormpath User model.
 * Extends LoopBack [UserModel](http://apidocs.strongloop.com./loopback/#user).
 *
 * Default `StormpathUser` ACLs.
 *
 * - DENY EVERYONE `*`
 * - ALLOW EVERYONE `create`
 * - ALLOW OWNER `deleteById`
 * - ALLOW EVERYONE `login`
 * - ALLOW EVERYONE `logout`
 * - ALLOW EVERYONE `findById`
 * - ALLOW OWNER `updateAttributes`
 *
 * @property {String} username Must be unique
 * @property {String} password Hidden from remote clients
 * @property {String} email Must be valid email / unique
 * @property {Boolean} emailVerified Set when a user's email has been verified via `confirm()`
 * @property {String} verificationToken Set when `verify()` is called
 * @property {Object} settings Extends the `Model.settings` object.
 * @property {Boolean} settings.emailVerificationRequired Require the email verification
 * process before allowing a login.
 * @property {Number} settings.ttl Default time to live (in seconds) for the `AccessToken` created by `User.login() / user.createAccessToken()`.
 * Default is `1209600` (2 weeks)
 * @property {Number} settings.maxTTL The max value a user can request a token to be alive / valid for.
 * Default is `31556926` (1 year)
 * @property {Boolean} settings.realmRequired Require a realm when logging in a user.
 * @property {String} settings.realmDelimiter When set a realm is required.
 * @property {Number} settings.resetPasswordTokenTTL Time to live for password reset `AccessToken`. Default is `900` (15 minutes).
 * @property {Number} settings.saltWorkFactor The `bcrypt` salt work factor. Default is `10`.
 *
 * @class StormpathUser
 * @inherits {User}
 */
module.exports = function(StormpathUser) {

  /**
   * Create access token for the logged in user. This method can be overridden to
   * customize how access tokens are generated
   *
   * @param {Number} ttl The requested ttl
   * @param {Object} [options] The options for access token, such as scope, appId
   * @callback {Function} cb The callback function
   * @param {String|Error} err The error string or object
   * @param {AccessToken} token The generated access token object
   */
  User.prototype.createAccessToken = function(ttl, options, cb) {
    if (cb === undefined && typeof options === 'function') {
      // createAccessToken(ttl, cb)
      cb = options;
      options = undefined;
    }
    if (typeof ttl === 'object' && !options) {
      // createAccessToken(options, cb)
      options = ttl;
      ttl = options.ttl;
    }
    options = options || {};
    var userModel = this.constructor;
    ttl = Math.min(ttl || userModel.settings.ttl, userModel.settings.maxTTL);
    this.accessTokens.create({
      ttl: ttl
    }, cb);
  };

  function splitPrincipal(name, realmDelimiter) {
    var parts = [null, name];
    if (!realmDelimiter) {
      return parts;
    }
    var index = name.indexOf(realmDelimiter);
    if (index !== -1) {
      parts[0] = name.substring(0, index);
      parts[1] = name.substring(index + realmDelimiter.length);
    }
    return parts;
  }

  /**
   * Normalize the credentials
   * @param {Object} credentials The credential object
   * @param {Boolean} realmRequired
   * @param {String} realmDelimiter The realm delimiter, if not set, no realm is needed
   * @returns {Object} The normalized credential object
   */
  StormpathUser.normalizeCredentials = function(credentials, realmRequired, realmDelimiter) {
    var query = {};
    credentials = credentials || {};
    if (!realmRequired) {
      if (credentials.email) {
        query.email = credentials.email;
      } else if (credentials.username) {
        query.username = credentials.username;
      }
    } else {
      if (credentials.realm) {
        query.realm = credentials.realm;
      }
      var parts;
      if (credentials.email) {
        parts = splitPrincipal(credentials.email, realmDelimiter);
        query.email = parts[1];
        if (parts[0]) {
          query.realm = parts[0];
        }
      } else if (credentials.username) {
        parts = splitPrincipal(credentials.username, realmDelimiter);
        query.username = parts[1];
        if (parts[0]) {
          query.realm = parts[0];
        }
      }
    }
    return query;
  };

  /**
   * Login a user by with the given `credentials`.
   *
   * ```js
   *    StormpathUser.login({username: 'foo', password: 'bar'}, function (err, token) {
  *      console.log(token.id);
  *    });
   * ```
   *
   * @param {Object} credentials username/password or email/password
   * @param {String[]|String} [include] Optionally set it to "user" to include
   * the user info
   * @callback {Function} callback Callback function
   * @param {Error} err Error object
   * @param {AccessToken} token Access token if login is successful
   */

  StormpathUser.login = function(credentials, include, fn) {
    var self = this;
    if (typeof include === 'function') {
      fn = include;
      include = undefined;
    }

    include = (include || '');
    if (Array.isArray(include)) {
      include = include.map(function(val) {
        return val.toLowerCase();
      });
    } else {
      include = include.toLowerCase();
    }

    var realmDelimiter;
    // Check if realm is required
    var realmRequired = !!(self.settings.realmRequired ||
      self.settings.realmDelimiter);
    if (realmRequired) {
      realmDelimiter = self.settings.realmDelimiter;
    }
    var query = self.normalizeCredentials(credentials, realmRequired,
      realmDelimiter);

    if (realmRequired && !query.realm) {
      var err1 = new Error('realm is required');
      err1.statusCode = 400;
      err1.code = 'REALM_REQUIRED';
      return fn(err1);
    }
    if (!query.email && !query.username) {
      var err2 = new Error('username or email is required');
      err2.statusCode = 400;
      err2.code = 'USERNAME_EMAIL_REQUIRED';
      return fn(err2);
    }

    self.findOne({where: query}, function(err, user) {
      var defaultError = new Error('login failed');
      defaultError.statusCode = 401;
      defaultError.code = 'LOGIN_FAILED';

      function tokenHandler(err, token) {
        if (err) return fn(err);
        if (Array.isArray(include) ? include.indexOf('user') !== -1 : include === 'user') {
          // NOTE(bajtos) We can't set token.user here:
          //  1. token.user already exists, it's a function injected by
          //     "AccessToken belongsTo StormpathUser" relation
          //  2. ModelBaseClass.toJSON() ignores own properties, thus
          //     the value won't be included in the HTTP response
          // See also loopback#161 and loopback#162
          token.__data.user = user;
        }
        fn(err, token);
      }

      if (err) {
        debug('An error is reported from StormpathUser.findOne: %j', err);
        fn(defaultError);
      } else if (user) {
        user.hasPassword(credentials.password, function(err, isMatch) {
          if (err) {
            debug('An error is reported from StormpathUser.hasPassword: %j', err);
            fn(defaultError);
          } else if (isMatch) {
            if (self.settings.emailVerificationRequired && !user.emailVerified) {
              // Fail to log in if email verification is not done yet
              debug('StormpathUser email has not been verified');
              err = new Error('login failed as the email has not been verified');
              err.statusCode = 401;
              err.code = 'LOGIN_FAILED_EMAIL_NOT_VERIFIED';
              return fn(err);
            } else {
              if (user.createAccessToken.length === 2) {
                user.createAccessToken(credentials.ttl, tokenHandler);
              } else {
                user.createAccessToken(credentials.ttl, credentials, tokenHandler);
              }
            }
          } else {
            debug('The password is invalid for user %s', query.email || query.username);
            fn(defaultError);
          }
        });
      } else {
        debug('No matching record is found for user %s', query.email || query.username);
        fn(defaultError);
      }
    });
  };

  /**
   * Logout a user with the given accessToken id.
   *
   * ```js
   *    StormpathUser.logout('asd0a9f8dsj9s0s3223mk', function (err) {
  *      console.log(err || 'Logged out');
  *    });
   * ```
   *
   * @param {String} accessTokenID
   * @callback {Function} callback
   * @param {Error} err
   */

  StormpathUser.logout = function(tokenId, fn) {
    this.relations.accessTokens.modelTo.findById(tokenId, function(err, accessToken) {
      if (err) {
        fn(err);
      } else if (accessToken) {
        accessToken.destroy(fn);
      } else {
        fn(new Error('could not find accessToken'));
      }
    });
  };

  /**
   * Compare the given `password` with the users hashed password.
   *
   * @param {String} password The plain text password
   * @returns {Boolean}
   */

  StormpathUser.prototype.hasPassword = function(plain, fn) {
    if (this.password && plain) {
      bcrypt.compare(plain, this.password, function(err, isMatch) {
        if (err) return fn(err);
        fn(null, isMatch);
      });
    } else {
      fn(null, false);
    }
  };

  /**
   * Verify a user's identity by sending them a confirmation email.
   *
   * ```js
   *    var options = {
   *      type: 'email',
   *      to: user.email,
   *      template: 'verify.ejs',
   *      redirect: '/',
   *      tokenGenerator: function (user, cb) { cb("random-token"); }
   *    };
   *
   *    user.verify(options, next);
   * ```
   *
   * @options {Object} options
   * @property {String} type Must be 'email'.
   * @property {String} to Email address to which verification email is sent.
   * @property {String} from Sender email addresss, for example
   *   `'noreply@myapp.com'`.
   * @property {String} subject Subject line text.
   * @property {String} text Text of email.
   * @property {String} template Name of template that displays verification
   *  page, for example, `'verify.ejs'.
   * @property {String} redirect Page to which user will be redirected after
   *  they verify their email, for example `'/'` for root URI.
   * @property {Function} generateVerificationToken A function to be used to
   *  generate the verification token. It must accept the user object and a
   *  callback function. This function should NOT add the token to the user
   *  object, instead simply execute the callback with the token! StormpathUser saving
   *  and email sending will be handled in the `verify()` method.
   */
  //StormpathUser.prototype.verify = function(options, fn) {
  //  var user = this;
  //  var userModel = this.constructor;
  //  assert(typeof options === 'object', 'options required when calling user.verify()');
  //  assert(options.type, 'You must supply a verification type (options.type)');
  //  assert(options.type === 'email', 'Unsupported verification type');
  //  assert(options.to || this.email, 'Must include options.to when calling user.verify() or the user must have an email property');
  //  assert(options.from, 'Must include options.from when calling user.verify() or the user must have an email property');

  //  options.redirect = options.redirect || '/';
  //  options.template = path.resolve(options.template || path.join(__dirname, '..', '..', 'templates', 'verify.ejs'));
  //  options.user = this;
  //  options.protocol = options.protocol || 'http';

  //  var app = userModel.app;
  //  options.host = options.host || (app && app.get('host')) || 'localhost';
  //  options.port = options.port || (app && app.get('port')) || 3000;
  //  options.restApiRoot = options.restApiRoot || (app && app.get('restApiRoot')) || '/api';
  //  options.verifyHref = options.verifyHref ||
  //    options.protocol +
  //    '://' +
  //    options.host +
  //    ':' +
  //    options.port +
  //    options.restApiRoot +
  //    userModel.http.path +
  //    userModel.sharedClass.find('confirm', true).http.path +
  //    '?uid=' +
  //    options.user.id +
  //    '&redirect=' +
  //    options.redirect;

  //  // Email model
  //  var Email = options.mailer || this.constructor.email || loopback.getModelByType(loopback.Email);

  //  // Set a default token generation function if one is not provided
  //  var tokenGenerator = options.generateVerificationToken || StormpathUser.generateVerificationToken;

  //  tokenGenerator(user, function(err, token) {
  //    if (err) { return fn(err); }

  //    user.verificationToken = token;
  //    user.save(function(err) {
  //      if (err) {
  //        fn(err);
  //      } else {
  //        sendEmail(user);
  //      }
  //    });
  //  });

  //  // TODO - support more verification types
  //  function sendEmail(user) {
  //    options.verifyHref += '&token=' + user.verificationToken;

  //    options.text = options.text || 'Please verify your email by opening this link in a web browser:\n\t{href}';

  //    options.text = options.text.replace('{href}', options.verifyHref);

  //    var template = loopback.template(options.template);
  //    Email.send({
  //      to: options.to || user.email,
  //      from: options.from,
  //      subject: options.subject || 'Thanks for Registering',
  //      text: options.text,
  //      html: template(options),
  //      headers: options.headers || {}
  //    }, function(err, email) {
  //      if (err) {
  //        fn(err);
  //      } else {
  //        fn(null, {email: email, token: user.verificationToken, uid: user.id});
  //      }
  //    });
  //  }
  //};

  /**
   * A default verification token generator which accepts the user the token is
   * being generated for and a callback function to indicate completion.
   * This one uses the crypto library and 64 random bytes (converted to hex)
   * for the token. When used in combination with the user.verify() method this
   * function will be called with the `user` object as it's context (`this`).
   *
   * @param {object} user The StormpathUser this token is being generated for.
   * @param {Function} cb The generator must pass back the new token with this function call
   */
  //StormpathUser.generateVerificationToken = function(user, cb) {
  //  crypto.randomBytes(64, function(err, buf) {
  //    cb(err, buf && buf.toString('hex'));
  //  });
  //};

  /**
   * Confirm the user's identity.
   *
   * @param {Any} userId
   * @param {String} token The validation token
   * @param {String} redirect URL to redirect the user to once confirmed
   * @callback {Function} callback
   * @param {Error} err
   */
  StormpathUser.confirm = function(uid, token, redirect, fn) {
    this.findById(uid, function(err, user) {
      if (err) {
        fn(err);
      } else {
        if (user && user.verificationToken === token) {
          user.verificationToken = undefined;
          user.emailVerified = true;
          user.save(function(err) {
            if (err) {
              fn(err);
            } else {
              fn();
            }
          });
        } else {
          if (user) {
            err = new Error('Invalid token: ' + token);
            err.statusCode = 400;
            err.code = 'INVALID_TOKEN';
          } else {
            err = new Error('StormpathUser not found: ' + uid);
            err.statusCode = 404;
            err.code = 'USER_NOT_FOUND';
          }
          fn(err);
        }
      }
    });
  };

  /**
   * Create a short lived acess token for temporary login. Allows users
   * to change passwords if forgotten.
   *
   * @options {Object} options
   * @prop {String} email The user's email address
   * @callback {Function} callback
   * @param {Error} err
   */
  //StormpathUser.resetPassword = function(options, cb) {
  //  var StormpathUserModel = this;
  //  var ttl = StormpathUserModel.settings.resetPasswordTokenTTL || DEFAULT_RESET_PW_TTL;

  //  options = options || {};
  //  if (typeof options.email === 'string') {
  //    StormpathUserModel.findOne({ where: {email: options.email} }, function(err, user) {
  //      if (err) {
  //        cb(err);
  //      } else if (user) {
  //        // create a short lived access token for temp login to change password
  //        // TODO(ritch) - eventually this should only allow password change
  //        user.accessTokens.create({ttl: ttl}, function(err, accessToken) {
  //          if (err) {
  //            cb(err);
  //          } else {
  //            cb();
  //            StormpathUserModel.emit('resetPasswordRequest', {
  //              email: options.email,
  //              accessToken: accessToken,
  //              user: user
  //            });
  //          }
  //        });
  //      } else {
  //        cb();
  //      }
  //    });
  //  } else {
  //    var err = new Error('email is required');
  //    err.statusCode = 400;
  //    err.code = 'EMAIL_REQUIRED';
  //    cb(err);
  //  }
  //};

  StormpathUser.validatePassword = function(plain) {
    if (typeof plain === 'string' && plain) {
      return true;
    }
    var err =  new Error('Invalid password: ' + plain);
    err.statusCode = 422;
    throw err;
  };

  /*!
   * Setup an extended user model.
   */

  StormpathUser.setup = function() {
    // We need to call the base class's setup method
    StormpathUser.base.setup.call(this);
    var StormpathUserModel = this;

    // max ttl
    this.settings.maxTTL = this.settings.maxTTL || DEFAULT_MAX_TTL;
    this.settings.ttl = this.settings.ttl || DEFAULT_TTL;

    // Make sure emailVerified is not set by creation
    StormpathUserModel.beforeRemote('create', function(ctx, user, next) {
      var body = ctx.req.body;
      if (body && body.emailVerified) {
        body.emailVerified = false;
      }
      next();
    });

    StormpathUserModel.remoteMethod(
      'login',
      {
        description: 'Login a user with username/email and password',
        accepts: [
          {arg: 'credentials', type: 'object', required: true, http: {source: 'body'}},
          {arg: 'include', type: 'string', http: {source: 'query' },
            description: 'Related objects to include in the response. ' +
            'See the description of return value for more details.'}
        ],
        returns: {
          arg: 'accessToken', type: 'object', root: true,
          description:
            'The response body contains properties of the AccessToken created on login.\n' +
            'Depending on the value of `include` parameter, the body may contain ' +
            'additional properties:\n\n' +
            '  - `user` - `{StormpathUser}` - Data of the currently logged in user. (`include=user`)\n\n'
        },
        http: {verb: 'post'}
      }
    );

    StormpathUserModel.remoteMethod(
      'logout',
      {
        description: 'Logout a user with access token',
        accepts: [
          {arg: 'access_token', type: 'string', required: true, http: function(ctx) {
            var req = ctx && ctx.req;
            var accessToken = req && req.accessToken;
            var tokenID = accessToken && accessToken.id;

            return tokenID;
          }, description: 'Do not supply this argument, it is automatically extracted ' +
            'from request headers.'
          }
        ],
        http: {verb: 'all'}
      }
    );

    //StormpathUserModel.remoteMethod(
    //  'confirm',
    //  {
    //    description: 'Confirm a user registration with email verification token',
    //    accepts: [
    //      {arg: 'uid', type: 'string', required: true},
    //      {arg: 'token', type: 'string', required: true},
    //      {arg: 'redirect', type: 'string'}
    //    ],
    //    http: {verb: 'get', path: '/confirm'}
    //  }
    //);

    //StormpathUserModel.remoteMethod(
    //  'resetPassword',
    //  {
    //    description: 'Reset password for a user with email',
    //    accepts: [
    //      {arg: 'options', type: 'object', required: true, http: {source: 'body'}}
    //    ],
    //    http: {verb: 'post', path: '/reset'}
    //  }
    //);

    StormpathUserModel.on('attached', function() {
      StormpathUserModel.afterRemote('confirm', function(ctx, inst, next) {
        if (ctx.args.redirect !== undefined) {
          if (!ctx.res) {
            return next(new Error('The transport does not support HTTP redirects.'));
          }
          ctx.res.location(ctx.args.redirect);
          ctx.res.status(302);
        }
        next();
      });
    });

    // default models
    assert(loopback.Email, 'Email model must be defined before StormpathUser model');
    StormpathUserModel.email = loopback.Email;

    assert(loopback.AccessToken, 'AccessToken model must be defined before StormpathUser model');
    StormpathUserModel.accessToken = loopback.AccessToken;

    return StormpathUserModel;
  };

  /*!
   * Setup the base user.
   */

  StormpathUser.setup();

};
