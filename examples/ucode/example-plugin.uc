'use strict';

let ubus = require('ubus').connect();

/*
 * An ucode plugin script is supposed to return a signature object on
 * invocation which describes the ubus objects the plugin script wants to
 * register, as well as the related methods and their argument signatures.
 */
return {
	/*
	 * Each toplevel key of the returned signature object corresponds to the
	 * name of an ubus object to register.
	 *
	 * The value of each key must be a nested dictionary describing the object
	 * methods.
	 */
	example_object_1: {
		/*
		 * Each key within the nested dictionary refers to the name of a method
		 * to define for the parent object.
		 *
		 * The value of each method name key must be another nested dictionary
		 * describing the method.
		 */
		method_1: {
			/*
			 * At the very least, each method description dictionary *must*
			 * contain a key "call" with the ucode callback function to call
			 * when the corresponding ubus object method is invoked.
			 *
			 * The callback function is supposed to return a dictionary which
			 * is automatically translated into a nested blobmsg structure and
			 * sent back as ubus reply.
			 *
			 * Non-dictionary return values are discarded and the ubus method
			 * call will fail with UBUS_STATUS_NO_DATA.
			 */
			call: function() {
				return { hello: "world" };
			}
		},

		method_2: {
			/*
			 * Additionally, method descriptions *may* supply an "args" key
			 * referring to a dictionary describing the ubus method call
			 * arguments accepted.
			 *
			 * The resulting method argument policy is also published to ubus
			 * and visible with "ubus -v list".
			 *
			 * The callback function will receive a dictionary containing the
			 * received named arguments as first argument. Only named arguments
			 * present in the "args" dictionary are accepted. Attempts to invoke
			 * ubus methods with arguments not mentioned here or with argument
			 * values not matching the given type hints are rejected with
			 * UBUS_STATUS_INVALID_ARGUMENT.
			 *
			 * The expected data type of each named argument is inferred from
			 * the ucode value within the "args" dictionary:
			 *
			 * ucode type | ucode value | blob type
			 * -----------+-------------+--------------------
			 * integer    |           8 | BLOBMSG_TYPE_INT8
			 * integer    |          16 | BLOBMSG_TYPE_INT16
			 * integer    |          64 | BLOBMSG_TYPE_INT64
			 * integer    | any integer | BLOBMSG_TYPE_INT32
			 * boolean    | true, false | BLOBMSG_TYPE_INT8
			 * string     |  any string | BLOBMSG_TYPE_STRING
			 * double     |  any double | BLOBMSG_TYPE_DOUBLE
			 * array      |   any array | BLOBMSG_TYPE_ARRAY
			 * object     |  any object | BLOBMSG_TYPE_TABLE
			 *
			 * The ucode callback function will also receive auxillary status
			 * information about the ubus request within a dictionary passed as
			 * second argument to it. The dictionary will contain details about
			 * the invoked object, the invoked method name (useful in case
			 * multiple methods share the same callback) and the effective ubusd
			 * ACL for this request.
			 */
			args: {
				foo: 32,
				bar: 64,
				baz: true,
				qrx: "example"
			},

			call: function(request) {
				return {
					got_args: request.args,
					got_info: request.info
				};
			}
		},

		method_3: {
			call: function(request) {
				/*
				 * Process exit codes are automatically translated to ubus
				 * error status codes. Exit code values outside of the
				 * representable status range are converted to
				 * UBUS_STATUS_UNKNOWN_ERROR.
				 */
				if (request.info.acl.user != "root")
					exit(UBUS_STATUS_PERMISSION_DENIED);

				/*
				 * To invoke nested ubus requests without potentially blocking
				 * rpcd's main loop, use the ubus.defer() method to start an
				 * asynchronous request and issue request.reply() from within
				 * the completion callback. It is important to return the deferred
				 * request value produced by ubus.call_async() to instruct rpcd to
				 * await the completion of the nested request.
				 */
				return ubus.defer('example_object_2', 'method_a', { number: 5 },
					function(code, reply) {
						request.reply({
							res: reply,
							req: request.info
						}, UBUS_STATUS_OK);
					});
			}
		},

		method_4: {
			call: function() {
				/*
				 * Runtime exceptions are catched by rpcd, the corresponding
				 * request is replied to with UBUS_STATUS_UNKNOWN_ERROR.
				 */
				die("An error occurred");
			}
		}
	},

	example_object_2: {
		method_a: {
			args: { number: 123 },
			call: function(request) {
				/*
				 * Instead of returning the reply, we can also use the reply
				 * method of the request object.
				 */
				request.reply({ got_number: request.args.number });
			}
		}
	}
};
