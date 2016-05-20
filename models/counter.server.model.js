var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var CounterSchema = new Schema({
	_id: {
		type: String,
		required: true
	},
	seq: {
		type: Number,
		default: 1
	}
});
var Counter = mongoose.model('Counter', CounterSchema);

// Initialize Collection

Counter.findById('OrderId', function(err, counter) {
	if (err) {
		console.log(err.message);
	}

	if (counter === null) {
		var newCounter = new Counter({
			_id: 'OrderId'
		});
		newCounter.save(function(err) {
			if (err) {
				console.log(err.message);
			}
		});
	}
});

module.exports = Counter;