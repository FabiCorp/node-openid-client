/* eslint-disable global-require, import/no-dynamic-require */

const http = require('http');

const makeError = require('make-error');

function HTTPError(response) {
  const statusMessage = http.STATUS_CODES[response.statusCode];
  HTTPError.super.call(this, `Response code ${response.statusCode} (${statusMessage})`);

  Object.assign(
    this,
    {
      statusCode: response.statusCode,
      statusMessage,
      headers: response.headers,
      response,
    }
  );
}

makeError(HTTPError);

/*
 * url {String}
 * options {Object}
 * options.headers {Object}
 * options.body {String|Object}
 * options.form {Boolean}
 * options.query {Object}
 * options.timeout {Number}
 * options.retries {Number}
 * options.followRedirect {Boolean}
 */

const requestLibraryName = 'request';
module.exports = function requestWrapper() {
  // intended use of non-global & dynamic require
  // webpack will not include "request" in the bundle now
  const request = require(requestLibraryName);

  function requestWrap(method, url, options) {
    if (options.form) {
      options.form = options.body;
      options.body = undefined;
    }
    return new Promise((resolve, reject) => {
      request({
        method,
        url,
        headers: options.headers,
        qs: options.query,
        body: options.body,
        form: options.form,
        followRedirect: options.followRedirect,
        timeout: options.timeout,
      }, (error, response, body) => {
        if (error) {
          reject(error);
        } else {
          response.body = body;
          const { statusCode } = response;
          const limitStatusCode = options.followRedirect ? 299 : 399;

          if (statusCode !== 304 && (statusCode < 200 || statusCode > limitStatusCode)) {
            reject(new HTTPError(response));
            return;
          }

          resolve(response);
        }
      });
    });
  }

  return {
    HTTPError,
    get(url, options) {
      return requestWrap('GET', url, options);
    },
    post(url, options) {
      return requestWrap('POST', url, options);
    },
  };
};
