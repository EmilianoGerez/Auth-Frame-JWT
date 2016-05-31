/*
 // Signup Workflow
 Create user
 SendEmail [sendEmail]
 generate code [generateCode] (code = cipher userId + (actual Date + 2 days))
 generate template (for activation account or reset pass)
 setup email [setupEmail]
 send email

 // Activate Account WorkFlow
 [activate]
 [verifyCode] (decrypt code, check valid and expiration)
 Update user

 // Send Activation Workflow
 [sendActivation]
 [findUserByEmail]
 [sendEmail]

 // Login Workflow
 Find User
 [loginProcess]
 [getDeviceData] (device data for create session by agent-device)
 [cleanSessions] (remove old and expired sessions)
 [createSession]
 [createToken]   (create jwt and return this)

 // Refresh Token Workflow
 [tokenVerify]
 [getDeviceData] (for find current session)
 [verifySession] (check expiration session)
 [createToken] (send a new jwt)

 // Logout Workflow
 Find user
 check params (for close current session or specific session)
 specific session
 [cleanSession]
 [updateSession]
 current session
 [getDeviceData]
 [cleanSession]
 [updateSession]

 */

var mongoose = require('mongoose');
var User = mongoose.model('User');
var jwt = require('jsonwebtoken');
var tokenConfig = require('../configs/token.server.config.js');
var emailConfig = require('../configs/email.server.config.js');
var useragent = require('useragent');
var nodemailer = require('nodemailer');
var _ = require('lodash');
var async = require('async');
var getmac = require('getmac');
var crypto = require('crypto');
var moment = require('moment');
var emailTemplate = require('../controllers/helpers/email-template.server');


//////////////////////////////////////
//  CONFIGURATIONS
/////////////////////////////////////

// array of ignored user attributes in token content
var ignoreAttr = ['__v', 'password', 'sessions', 'firstName', 'lastName', 'active', 'facebook'];

// create reusable transporter object using SMTP transport
var transporter = nodemailer.createTransport({
    service: emailConfig.SERVICE,
    auth: {
        user: emailConfig.USER,
        pass: emailConfig.PASS
    }
});

//////////////////////////////////////
//  EXPORT HELPER METHODS
/////////////////////////////////////
exports.sendemail = function (req, user, isReset, callback) {
    sendEmail(req, user, isReset, callback);
};

//////////////////////////////////////
//  PUBLIC METHODS
/////////////////////////////////////

// Activate account
exports.activate = function (req, res) {
    var code = req.body.code;

    var codeVerify = verifyCode(code);

    if (!codeVerify.isValid) {
        res.status(codeVerify.status).jsonp(codeVerify.res);
        return;
    }

    User.findByIdAndUpdate(
        codeVerify.userId,
        {$set: {active: true}},
        function (err) {
            if (err) {
                return res.status(500).jsonp(err.message);
            }

            return res.status(200).jsonp({
                message: 'Activation successful'
            });
        });

};

// send a new activation email
exports.sendActivation = function (req, res) {
    async.waterfall([
        async.apply(findUserByEmail, req),
        sendEmail
    ], function (err) {
        if (err) {
            return res.status(err.status).jsonp(err.res);
        }

        return res.status(200).jsonp({
            message: 'Activation email sent successfully'
        });
    });
};

/// User SignIn
exports.login = function (req, res) {

    // check form data
    if (!req.body.email || !req.body.password) {
        return res.status(400).jsonp({
            error: 'blankCredentials',
            message: "Email or Password can't be blank"
        });
    }

    User.findOne({
        email: req.body.email
    }, function (err, user) {
        if (err) {
            return res.status(500).jsonp(err);
        }

        if (!user) {
            return res.status(404).jsonp({
                error: 'credentials',
                message: "Invalid email or password"
            });
        }

        if (!user.active) {
            return res.status(401).jsonp({
                error: 'activation',
                message: 'This account needs activation. Please check your email account'
            });
        }

        if (!user.validPassword(req.body.password)) {
            return res.status(401).jsonp({
                error: 'credentials',
                message: 'Invalid email or password'
            });
        }

        // clean expired token > create refresh token > get token > return new token
        return loginProcess(req, res, user);
    });
};

// refresh token process
exports.refreshToken = function (req, res) {
    async.waterfall([
        async.apply(tokenVerify, req),
        getDeviceData,
        verifySession,
        createToken
    ], function (err, token) {
        if (err) {
            return res.status(err.status).jsonp(err.res);
        }
        return res.status(200).jsonp({
            token: token
        });
    });
};

/// User logout
exports.logout = function (req, res) {

    if (!req.params.id) {
        res.status(404).jsonp({
            message: 'Invalid params'
        });
    }

    User.findById(req.params.id,
        function (err, user) {
            if (err) {
                return res.status(500).jsonp(err.message);
            }

            if (!user) {
                return res.status(404).jsonp({
                    message: "User doesn't exist"
                });
            }

            var asyncOperations;

            if (req.params.sessionId !== 'null') {
                var device;
                var agent;

                user.sessions.forEach(function (session) {
                    if (session._id == req.params.sessionId) {
                        device = session.device;
                        agent = {
                            os: session.os,
                            browser: session.browser
                        };
                    }
                });

                asyncOperations = [
                    async.apply(cleanSessions, user, agent, device),
                    updateSessions
                ];
            } else {
                asyncOperations = [
                    async.apply(getDeviceData, user, req),
                    cleanSessions,
                    updateSessions
                ];
            }

            // clean session
            async.waterfall(asyncOperations, function (err) {
                if (err) {
                    return res.status(500).jsonp(err.res);
                }

                return res.status(200).jsonp({
                    message: 'Session closed'
                });
            });
        });
};

/// User Autorization
exports.isAuth = function (req, res, next) {

    var token = req.headers['x-access-token'] || req.headers.authorization;

    // angular js headers
    if (req.headers.authorization) {
        token = token.split(" ")[1];
    }

    if (!token) {
        return res.status(403).jsonp({
            message: 'Invalid Headers'
        });
    }

    jwt.verify(token, tokenConfig.SECRET_KEY, function (err, decoded) {
        if (err) {
            return res.status(403).jsonp({
                message: 'Invalid credentials'
            });
        } else {
            req.decoded = decoded;
            next();
        }
    });

};


/// Admin Autorization [this method needs require isAuth() first]
exports.isAdmin = function (req, res, next) {
    if (req.decoded.role === 'Admin') {
        next();
    } else {
        return res.status(401).jsonp({
            message: 'You do not have permission'
        });
    }
};

/// User forgot password
exports.forgot = function (req, res) {

    async.waterfall([
        async.apply(getUserAndCloseSessions, req),
        sendEmail
    ], function (err, info) {
        if (err) {
            return res.status(err.status).jsonp(err.res);
        }
        return res.status(200).jsonp({
            data: info,
            message: 'Success!! Check your email'
        });
    });
};

/// Reset password
exports.reset = function (req, res) {
    var code = req.body.code;
    var password = req.body.password;

    if (!code || !password) {
        return res.status(403).jsonp({
            message: 'Invalid code or Password'
        });
    }

    var codeVerify = verifyCode(code);

    if (!codeVerify.isValid) {
        return res.status(codeVerify.status).jsonp(codeVerify.res);
    }


    User.findById(codeVerify.userId, function (err, user) {
        if (err) {
            return res.status(500).jsonp(err);
        }

        user.password = user.generateHash(req.body.password);

        user.save(function (err) {
            if (err) {
                return res.status(500).jsonp(err);
            }
            return res.status(200).jsonp({
                message: 'Success! Password updated'
            });
        });
    });
};

//////////////////////////////////////
//  HELPERS METHODS
/////////////////////////////////////
// find user by email [sendActivation]
function findUserByEmail(req, callback) {
    User.findOne({email: req.body.email}, function (err, user) {
        var error;
        if (err) {
            error = {
                status: 500,
                res: {
                    error: 'internal',
                    message: err.message
                }
            };
            return callback(error, null);
        }

        if (!user) {
            error = {
                status: 404,
                res: {
                    error: 'invalidEmail',
                    message: 'Invalid email'
                }
            };
            return callback(error, null);
        }

        return callback(null, req, user, false);

    });
}

// clean expired token > create refresh token > get token > send new token
function loginProcess(req, res, user) {

    async.waterfall([
        async.apply(getDeviceData, user, req),
        cleanSessions,
        createSession,
        updateSessions,
        createToken
    ], function (err, token, user) {
        if (err) {
            return res.status(500).jsonp(err.res);
        }

        // remove refresh token for send to the client
        user.sessions.forEach(function (session) {
            session.token = undefined;
        });

        return res.status(200).jsonp({
            token: token,
            user: user
        });
    });

}

// create a new session and update sessions array [login process]
function getDeviceData(user, req, callback) {

    // get the user agent
    var agent = getAgent(req);

    // get the user mac address
    getmac.getMac(function (err, mac) {
        if (err) {
            console.log(err);
        }
        return callback(null, user, agent, mac);
    });
}

// remove expired sessions and old session for current device [login process]
function cleanSessions(user, agent, mac, callback) {

    if (user.sessions.length <= 0) {
        return callback(null, user, agent, mac);
    }

    user.sessions = user.sessions.filter(function (session) {
        // remove old session of the current device
        if (session.device === mac && session.os === agent.os && session.browser === agent.browser) {
            return;
        } else {
            // verify refresh token - use try because callback loose the scope
            try {
                jwt.verify(session.token, tokenConfig.SECRET_KEY);
            } catch (err) {
                return;
            }
        }
        return session;
    });

    return callback(null, user, agent, mac);
}

// [login process]
function createSession(user, agent, userMac, callback) {

    // create refresh token - long-live JWT
    var token = jwt.sign({user: user._id}, tokenConfig.SECRET_KEY, {
        expiresIn: tokenConfig.SESSION_TIME
    });
    // push the new session
    user.sessions.push({
        token: token,
        os: agent.os,
        browser: agent.browser,
        device: userMac || 'undefined'
    });

    return callback(null, user, agent, userMac);

}

// add the new session to sessions array [login process]
function updateSessions(user, agent, userMac, callback) {

    // update current user sessions array
    User.findByIdAndUpdate(user._id,

        {
            $set: {
                sessions: user.sessions
            }
        },
        {
            'new': true, 'safe': true
        },
        function (err, user) {
            if (err) {
                return callback(err, null);
            }
            // hidden attr
            user.password = undefined;

            return callback(null, user);
        }
    );
}

// Create a shot live JWT [login process]
function createToken(user, callback) {
    var payload = {};

    // dinamyc assing atrr to payload [config ignored attrs]
    _.mapKeys(user._doc, function (value, key) {
        if (_.indexOf(ignoreAttr, key) === -1) {
            payload[key] = value;
        }
    });

    var token = jwt.sign(payload, tokenConfig.SECRET_KEY, {
        expiresIn: tokenConfig.EXP_TIME
    });

    return callback(null, token, user);
}

// verify user token [refresh token]
function tokenVerify(req, callback) {
    var token = req.headers['x-access-token'] || req.headers.authorization;
    var error;

    if (!token) {
        error = {
            status: 401,
            res: {
                message: 'Invalid credentials'
            }
        };
        return callback(error, null);
    }

    jwt.verify(token, tokenConfig.SECRET_KEY, function (err, decoded) {
        if (err && err.name !== 'TokenExpiredError') {
            error = {
                status: 401,
                res: {
                    message: 'Invalid token'
                }
            };
            return callback(error, null);
        }
        // if has err, decoded is undefined
        var payload = (decoded) ? decoded : jwt.decode(token);

        return callback(null, payload, req);
    });
}

function verifySession(decodedToken, agent, mac, callback) {
    var error;
    // find user and verify current session
    User.findById(decodedToken._id, function (err, user) {
        if (err) {
            error = {
                status: 500,
                res: {
                    message: 'Server error'
                }
            };
            return callback(error, null);
        }
        var flag;
        var length = user.sessions.length;

        //find current session
        user.sessions.forEach(function (session, index) {
            if (session.device === mac && session.os === agent.os && session.browser === agent.browser) {
                // verify refresh token
                try {
                    jwt.verify(session.token, tokenConfig.SECRET_KEY);
                    return callback(null, user);
                } catch (err) {
                    error = {
                        status: 401,
                        res: {
                            message: 'Session expired'
                        }
                    };
                    return callback(error, null);
                }
            }
            if (index === length - 1) {
                flag = true;
            }

        });

        if (flag) {
            // no session
            error = {
                status: 404,
                res: {
                    message: 'No session'
                }
            };
            return callback(error, null);
        }
    });

}


// get user agent data
function getAgent(req) {
    // fetch user agent
    var agent = useragent.parse(req.headers['user-agent']);
    return {
        os: agent.os.toString(),
        browser: agent.toAgent()
    };
}

// get user for forgot method
function getUserAndCloseSessions(req, callback) {
    User.findOneAndUpdate(
        {email: req.body.email},
        {$set: {sessions: []}},
        {new: true, safe: true},
        function (err, user) {
            var error;
            if (err) {
                error = {
                    status: 500,
                    res: {
                        message: err.message
                    }
                };
                return callback(error, null);
            }
            if (!user) {
                error = {
                    status: 404,
                    res: {
                        error: 'invalidEmail',
                        message: 'Invalid email'
                    }
                };
                return callback(error, null);
            }

            return callback(null, req, user, true);
        });
}

// send restore account email [forgot]
function sendEmail(req, user, isReset, callback) {

    var path = (isReset) ? emailConfig.RESET_PATH : emailConfig.ACTIVATION_PATH;
    var code = generateCode(user);
    var url = 'http://' + req.headers.host + path + code;
    var template = (isReset) ?
        emailTemplate.createResetTemplate(url, code, user.firstName) :
        emailTemplate.createActivationTemplate(url, code, user.firstName);
    var email = setupEmail(req, isReset, template);

    // send mail with defined transport object
    transporter.sendMail(email, function (err, info) {
        if (err) {
            var error = {
                status: 500,
                res: {
                    error: 'sending',
                    message: err
                }
            };
            return callback(error, null);
        }
        return callback(null, user);
    });
}

// setup email to send for reset account
function setupEmail(req, isReset, template) {
    return {
        from: emailConfig.USER, // sender address
        to: req.body.email, // list of receivers
        subject: (isReset) ? emailConfig.RESET_SUBJECT : emailConfig.ACTIVATE_SUBJECT, // Subject line
        html: template
    };
}

function generateCode(user) {
    var date = moment().add(2, 'days').unix();
    var data = user._id + ',' + date;
    var cipher = crypto.createCipher("aes192", "password");
    var crypted = cipher.update(data, 'utf8', 'hex');
    crypted += cipher.final('hex');
    return crypted;
}

function decryptCode(code) {
    var decipher = crypto.createDecipher("aes192", "password");
    var dec = decipher.update(code, 'hex', 'utf8');
    dec += decipher.final('utf8');
    return dec;
}

function verifyCode(code) {
    var data;

    try {
        data = decryptCode(code).split(',');
    } catch (err) {
        return {
            isValid: false,
            status: 401,
            res: {
                error: 'invalidCode',
                message: 'Invalid code'
            }
        };
    }

    var userId = data[0];
    var dateExpiration = data[1];
    var dateNow = moment().unix();

    // check expiration
    if (dateExpiration < dateNow) {
        return {
            isValid: false,
            status: 401,
            res: {
                error: 'expiredCode',
                message: 'Code expired'
            }
        };
    }

    return {
        isValid: true,
        userId: userId
    };
}