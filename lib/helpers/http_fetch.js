const http = require('http');
const querystring = require('querystring');
const url = require('url');

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

async function fetchWrap(method, uri, options) {
  const parsed = url.parse(uri, true);
  parsed.search = null;
  if (parsed.pathname === '/' && !uri.endsWith('/')) parsed.pathname = null;
  Object.assign(parsed.query, options.query);

  if (options.body && typeof options.body === 'object') {
    options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
    options.body = querystring.stringify(options.body);
  }

  const response = await fetch(url.format(parsed), { // eslint-disable-line no-undef
    method,
    mode: 'cors',
    credentials: 'omit',
    headers: options.headers,
    redirect: options.followRedirect ? 'follow' : 'manual',
    referrer: 'no-referrer',
    body: options.body,
  });

  const headers = {};
  for (const [key, value] of response.headers.entries()) { // eslint-disable-line no-restricted-syntax, max-len
    headers[key] = value;
  }
  Object.defineProperty(response, 'headers', { value: headers });

  if (response.type === 'opaqueredirect') {
    Object.defineProperty(response, 'status', { value: 302 });
  }

  Object.defineProperty(response, 'statusCode', { value: response.status, enumerable: false });
  Object.defineProperty(response, 'body', { value: await response.text(), writable: true });

  const { statusCode } = response;
  const limitStatusCode = options.followRedirect ? 299 : 399;

  if (statusCode !== 304 && (statusCode < 200 || statusCode > limitStatusCode)) {
    throw new HTTPError(response);
  }

  return response;
}

module.exports = function fetchWrapper() {
  return {
    HTTPError,
    get(uri, options) {
      return fetchWrap('GET', uri, options);
    },
    post(uri, options) {
      return fetchWrap('POST', uri, options);
    },
  };
};
