var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var bcrypt = require('bcrypt-nodejs');

var userSchema = new Schema({
    firstName: {
        type: String,
        required: true
    },
    lastName: {
        type: String,
        required: true
    },
    password: {
        type: String
    },
    role: {
        type: String,
        default: 'User',
        enum: ['Admin', 'User']
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    sessions: [{
        token: String,
        os: String,
        browser: String,
        device: String
    }],
    active: {
        type: Boolean,
        default: false
    },
    facebook: {
        id: String,
        token: String,
        email: String,
        firstName: String,
        lastName: String,
        avatar: String
    },
    google: {
        id: String,
        token: String,
        email: String,
        firstName: String,
        lastName: String,
        avatar: String
    }
});


// generating a hash
userSchema.methods.generateHash = function (password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
};

// checking if password is valid
userSchema.methods.validPassword = function (password) {
    return bcrypt.compareSync(password, this.password);
};

module.exports = mongoose.model('User', userSchema);
