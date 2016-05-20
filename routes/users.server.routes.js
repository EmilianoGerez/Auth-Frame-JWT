var express = require('express');
var router = express.Router();
var userCtrl = require('../controllers/user.server.controller');
var authCtrl = require('../auth/auth.controller.server.js');
var userValid = require('../validators/user.server.validator');

router.post('/', userValid.signupValidation, userCtrl.create);

router.get('/', authCtrl.isAuth, userCtrl.findAll);

router.get('/:id', authCtrl.isAuth, userCtrl.findOne);

router.put('/:id', authCtrl.isAuth, userCtrl.update);

router.delete('/:id', authCtrl.isAuth, userCtrl.remove);

router.get('/search/:email', userCtrl.isAvailable);

module.exports = router;
