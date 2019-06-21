var argscheck = require('cordova/argscheck'),
               exec = require('cordova/exec');

var touchid = {
	isAvailable: function(successCallback, errorCallback){
		exec(successCallback, errorCallback, "TouchID", "isAvailable", []);
	},
	save: function(tag, message, successCallback, errorCallback) {
		exec(successCallback, errorCallback, "TouchID", "save", [tag, message]);
	},
	verify: function(tag, message, token, successCallback, errorCallback){
		exec(successCallback, errorCallback, "TouchID", "verify", [tag, message, token]);
	},
	has: function(tag, successCallback, errorCallback){
		exec(successCallback, errorCallback, "TouchID", "has", [tag]);
	},
	delete: function(tag, successCallback, errorCallback){
		exec(successCallback, errorCallback, "TouchID", "delete", [tag]);
	},
	setLocale: function(locale, successCallback, errorCallback){
		exec(successCallback, errorCallback, "TouchID", "setLocale", [locale]);
	}
};

module.exports = touchid;
