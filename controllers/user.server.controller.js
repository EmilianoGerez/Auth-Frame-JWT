var mongoose = require('mongoose');
var User = mongoose.model('User');
var async = require('async');
var authCtrl = require('./../auth/auth.controller.server.js');

//////////////////////////////////////////////////////////
/// User SignUp
exports.create = function (req, res) {

    // create new user
    var newUser = new User();
    newUser.email = req.body.email;
    newUser.firstName = req.body.firstName;
    newUser.lastName = req.body.lastName;
    newUser.password = newUser.generateHash(req.body.password);
    if (req.body.role) {
        newUser.role = req.body.role;
    }
    //newUser.role = (req.body.code == userCodes.ADMIN_CODE) ? 'Admin' : 'Tech';

    async.waterfall([
        async.apply(userSave, req, newUser),
        authCtrl.sendemail
    ], function (err, user) {
        if (err) {
            return res.status(err.status).jsonp(err.res);
        }

        return res.status(201).jsonp(user);
    });
};

function userSave(req, newUser, callback) {
    newUser.save(function (err, user) {
        if (err) {
            var error = {
                status: 500,
                res: {
                    message: err.message
                }
            };
            return callback(error, null);
        }

        // remove pass value for send to the client
        user.password = undefined;

        return callback(null, req, user, false);

    });

}

//////////////////////////////////////////////////////////
/// Verify email is available
exports.isAvailable = function (req, res) {
    User.findOne({
        email: req.params.email
    }, function (err, user) {
        if (err) {
            return res.status(500).jsonp(err);
        }
        var isAvailable = (user) ? false : true;

        res.status(200).jsonp({
            available: isAvailable
        });
    });
};

//////////////////////////////////////////////////////////
/// List Users
exports.findAll = function (req, res) {
    User.find(function (err, users) {
        if (err) {
            res.status(500).send(err.message);
        }

        // remove pass value for send to the client
        users.forEach(function (user) {
            user.password = undefined;
            user.sessions.forEach(function (session) {
                session.token = undefined;
            });
        });

        res.status(200).jsonp(users);
    });
};

//////////////////////////////////////////////////////////
/// Find one user
exports.findOne = function (req, res) {
    User.findById(req.params.id, function (err, user) {
        if (err) {
            res.status(500).send(err.message);
        }

        // remove pass value for send to the client
        user.password = undefined;
        // remove refresh token for send to the client
        user.sessions.forEach(function (session) {
            session.token = undefined;
        });

        res.status(200).jsonp(user);
    });
};

//////////////////////////////////////////////////////////
/// Update a user
exports.update = function (req, res) {
    User.findById(req.params.id).exec(function (err, user) {
        if (err) {
            return res.status(500).jsonp(err);
        }

        if (!user) {
            return res.status(404).jsonp({
                message: 'User does not exist'
            })
        }

        user.firstName = req.body.firstName;
        user.lastName = req.body.lastName;
        // when user update the password, the req will have the new and old or current password
        if (req.body.password) {
            if (!user.validPassword(req.body.oldPassword)) {
                return res.status(401).jsonp({
                    error: 'currentPassword',
                    message: 'Invalid current password'
                });
            }

            user.password = user.generateHash(req.body.password);
            var responseType = 'passChanged';
            var responseMsg = 'Password changed successfully';
        }

        user.save(function (err) {
            if (err) {
                return res.status(500).jsonp(err);
            }

            // remove pass value for send to the client
            user.password = undefined;
            // remove refresh token for send to the client
            user.sessions.forEach(function (session) {
                session.token = undefined;
            });

            return res.status(200).jsonp({
                type: responseType || 'default',
                message: responseMsg || 'User update successfully',
                data: user
            });
        });
    });
};

//////////////////////////////////////////////////////////
/// Remove a user
exports.remove = function (req, res) {
    User.remove({
        '_id': req.params.id
    }, function (err) {
        if (err) {
            res.status(500).jsonp(err);
        }
        res.status(204).jsonp({
            'message': 'User delete successfully'
        });
    });
};
