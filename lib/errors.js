/* eslint-disable camelcase */
const { BaseError } = require('make-error');

class OIDCBaseError extends BaseError {}

class OIDCAssertionError extends BaseError {
  constructor({ message, actual, expected }) {
    super(message);
    this.expected = expected;
    this.actual = actual;
  }
}

class OIDCResponseError extends OIDCBaseError {
  constructor({
    error_description,
    error,
    error_uri,
    session_state,
    state,
    scope,
  }, response) {
    super(!error_description ? error : `${error} (${error_description})`);

    Object.assign(
      this,
      { error },
      (error_description && { error_description }),
      (error_uri && { error_uri }),
      (state && { state }),
      (scope && { scope }),
      (session_state && { session_state }),
    );

    Object.defineProperty(this, 'response', {
      value: response,
    });
  }
}

module.exports = {
  OIDCAssertionError,
  OIDCBaseError,
  OIDCResponseError,
};
