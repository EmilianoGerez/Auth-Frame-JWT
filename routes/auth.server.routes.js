var express = require('express');
var router = express.Router();
var authCtrl = require('../auth/auth.controller.server.js');
var userValid = require('../validators/user.server.validator');


router.post('/login', userValid.login, authCtrl.login);

router.get('/logout/:id/:device/:os/:browser', authCtrl.isAuth, authCtrl.logout);

router.post('/refresh', authCtrl.refreshToken);

router.post('/forgot', authCtrl.forgot);

router.post('/reset', authCtrl.reset);

router.post('/activation', authCtrl.activate);

router.post('/sendactivation', authCtrl.sendActivation);

module.exports = router;