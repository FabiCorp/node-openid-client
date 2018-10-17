const { OIDCResponseError } = require('../errors');

const isStandardBodyError = require('./is_standard_body_error');
const checkIfBearerHeaderOnlyError = require('./is_bearer_header_only_error');

module.exports = ({ bearerEndpoint = false } = {}) => function requestErrorHandler(err) {
  if (bearerEndpoint) {
    const [isBearerHeaderOnlyError, params] = checkIfBearerHeaderOnlyError.call(this, err);

    if (isBearerHeaderOnlyError) {
      throw new OIDCResponseError(params, err.response);
    }
  }

  if (isStandardBodyError.call(this, err)) {
    throw new OIDCResponseError(err.response.body, err.response);
  }

  throw err;
};
