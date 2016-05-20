// validation for signup form
exports.signupValidation = function (req, res, next) {

    req.sanitizeBody('firstName').trim();
    req.sanitizeBody('firstName').escape();
    req.sanitizeBody('lastName').trim();
    req.sanitizeBody('lastName').escape();
    req.sanitizeBody('email').trim();
    req.sanitizeBody('email').escape();
    req.sanitizeBody('password').trim();
    req.sanitizeBody('password').escape();

    req.checkBody('firstName', 'Debes introducir un nombre').notEmpty();
    req.checkBody('lastName', 'Debes introducir un apellido').notEmpty();
    req.checkBody('email', 'Debes introducir un email correcto').isEmail();
    req.checkBody('password', 'La contraseña debe contener entre 8 y 15 caracteres').len(8, 15);

    var errors = req.validationErrors();
    if (errors) {
        return res.status(500).jsonp(errors);
    }
    next();
};

// validation for login form
exports.login = function (req, res, next) {

    req.sanitizeBody('email').trim();
    req.sanitizeBody('email').escape();
    req.sanitizeBody('password').trim();
    req.sanitizeBody('password').escape();

    req.checkBody('email', 'Debes introducir un email correcto').isEmail();
    req.checkBody('password', 'La contraseña debe contener entre 8 y 15 caracteres').len(8, 15);

    var errors = req.validationErrors();
    if (errors) {
        return res.status(500).jsonp(errors);
    }
    next();
};

// validation for reset password
