const assert = require('assert');
const util = require('util');
const url = require('url');

const jose = require('node-jose');
const _ = require('lodash');
const pAny = require('p-any');
const LRU = require('lru-cache');

const httpGot = require('./helpers/http_got');
const httpRequest = require('./helpers/http_request');
const httpFetch = require('./helpers/http_fetch');
const errorHandler = require('./helpers/error_handler')();
const BaseClient = require('./client');
const registry = require('./issuer_registry');
const expectResponseWithBody = require('./helpers/expect_response')(200);
const webfingerNormalize = require('./util/webfinger_normalize');
const {
  DEFAULT_HTTP_OPTIONS, ISSUER_DEFAULTS, OIDC_DISCOVERY, OAUTH2_DISCOVERY, WEBFINGER, REL,
} = require('./helpers/consts');

const privateProps = new WeakMap();

let defaultHttpOptions = _.clone(DEFAULT_HTTP_OPTIONS);
let httpClient;

function instance(ctx) {
  if (!privateProps.has(ctx)) privateProps.set(ctx, { metadata: {} });
  return privateProps.get(ctx);
}

async function buildIssuerFromDiscovery(uri) {
  const response = await this.httpClient.get(uri, this.httpOptions());
  expectResponseWithBody(response);
  return new this(Object.assign({}, ISSUER_DEFAULTS, JSON.parse(response.body)));
}

class Issuer {
  /**
   * @name constructor
   * @api public
   */
  constructor(meta = {}) {
    ['introspection', 'revocation'].forEach((endpoint) => {
      // e.g. defaults introspection_endpoint to token_introspection_endpoint value
      if (
        meta[`${endpoint}_endpoint`] === undefined
        && meta[`token_${endpoint}_endpoint`] !== undefined
      ) {
        meta[`${endpoint}_endpoint`] = meta[`token_${endpoint}_endpoint`];
        delete meta[`token_${endpoint}_endpoint`];
      }

      // if intro/revocation endpoint auth specific meta is missing use the token ones if they
      // are defined
      if (
        meta[`${endpoint}_endpoint`]
        && meta[`${endpoint}_endpoint_auth_methods_supported`] === undefined
        && meta[`${endpoint}_endpoint_auth_signing_alg_values_supported`] === undefined
      ) {
        if (meta.token_endpoint_auth_methods_supported) {
          meta[`${endpoint}_endpoint_auth_methods_supported`] = meta.token_endpoint_auth_methods_supported;
        }
        if (meta.token_endpoint_auth_signing_alg_values_supported) {
          meta[`${endpoint}_endpoint_auth_signing_alg_values_supported`] = meta.token_endpoint_auth_signing_alg_values_supported;
        }
      }
    });

    Object.entries(meta).forEach(([key, value]) => {
      instance(this).metadata[key] = value;
      if (!this[key]) {
        Object.defineProperty(this, key, {
          get() { return instance(this).metadata[key]; },
        });
      }
    });

    instance(this).cache = new LRU({ max: 100 });

    registry.set(this.issuer, this);

    const self = this;

    Object.defineProperty(this, 'Client', {
      value: class Client extends BaseClient {
        static get issuer() {
          return self;
        }

        get issuer() {
          return this.constructor.issuer;
        }
      },
    });
  }

  /**
   * @name inspect
   * @api public
   */
  inspect() {
    return util.format('Issuer <%s>', this.issuer);
  }

  /**
   * @name keystore
   * @api private
   */
  async keystore(reload) {
    if (!this.jwks_uri) throw new Error('jwks_uri must be configured');

    const { keystore, cache } = instance(this);

    if (reload || !keystore) {
      cache.reset();
      try {
        const response = await this.httpClient.get(this.jwks_uri, this.httpOptions());
        expectResponseWithBody(response);
        const jwks = JSON.parse(response.body);
        const joseKeyStore = await jose.JWK.asKeyStore(jwks);
        cache.set('throttle', true, 60 * 1000);
        instance(this).keystore = joseKeyStore;
        return joseKeyStore;
      } catch (err) {
        errorHandler.call(this, err);
      }
    }

    return keystore;
  }

  /**
   * @name key
   * @api private
   */
  async key(def, allowMulti) {
    const { cache } = instance(this);

    // refresh keystore on every unknown key but also only upto once every minute
    const freshJwksUri = cache.get(def) || cache.get('throttle');

    const store = await this.keystore(!freshJwksUri);
    const { 0: key, length } = store.all(def);

    assert(length, 'no valid key found');
    if (!allowMulti) {
      assert.equal(length, 1, 'multiple matching keys, kid must be provided');
      cache.set(def, true);
    }
    return key;
  }

  /**
   * @name metadata
   * @api public
   */
  get metadata() {
    return instance(this).metadata;
  }

  /**
   * @name webfinger
   * @api public
   */
  static async webfinger(input) {
    const resource = webfingerNormalize(input);
    const { host } = url.parse(resource);
    const query = { resource, rel: REL };
    const opts = { query, followRedirect: true };
    const webfingerUrl = `https://${host}${WEBFINGER}`;

    const response = await this.httpClient.get(webfingerUrl, this.httpOptions(opts));
    const body = JSON.parse(response.body);

    const location = _.find(body.links, link => typeof link === 'object' && link.rel === REL && link.href);
    assert(location, 'no issuer found in webfinger');
    assert(typeof location.href === 'string' && location.href.startsWith('https://'), 'invalid issuer location');
    const expectedIssuer = location.href;

    if (registry.has(expectedIssuer)) {
      return registry.get(expectedIssuer);
    }

    const issuer = await this.discover(expectedIssuer);
    try {
      assert.equal(issuer.issuer, expectedIssuer, 'discovered issuer mismatch');
    } catch (err) {
      registry.delete(issuer.issuer);
      throw err;
    }

    return issuer;
  }

  /**
   * @name discover
   * @api public
   */
  static async discover(uri) {
    const parsed = url.parse(uri);

    // fast path, .well-known is in the uri
    if (parsed.pathname.includes('/.well-known/')) {
      return buildIssuerFromDiscovery.call(this, uri);
    }

    // handle OIDC Discovery 1.0 and RFC8414 simultaneously
    const uris = [];

    // given uri = https://op.example.com/path
    // as per RFC8414 https://op.example.com/.well-known/oauth-authorization-server/path
    if (parsed.pathname === '/') {
      uris.push(`${OAUTH2_DISCOVERY}`);
    } else {
      uris.push(`${OAUTH2_DISCOVERY}${parsed.pathname}`);
    }

    // given uri = https://op.example.com/path
    // as per Discovery 1.0 https://op.example.com/path/.well-known/openid-configuration
    if (parsed.pathname.endsWith('/')) {
      uris.push(`${parsed.pathname}${OIDC_DISCOVERY.substring(1)}`);
    } else {
      uris.push(`${parsed.pathname}${OIDC_DISCOVERY}`);
    }

    const issuer = await pAny(uris.map(async (pathname) => {
      const wellKnownUri = url.format(Object.assign({}, parsed, { pathname }));
      return buildIssuerFromDiscovery.call(this, wellKnownUri);
    }))
      .catch((err) => {
        if (err instanceof pAny.AggregateError) {
          const errors = err;
          for (const aErr of errors) { // eslint-disable-line no-restricted-syntax
            if (
              aErr instanceof this.httpClient.HTTPError
              || (aErr.message && aErr.message.includes('expected 200 OK with body, got '))
              || aErr instanceof SyntaxError
            ) {
              throw aErr;
            }
          }
        }

        throw err;
      })
      .catch(errorHandler.bind(this));

    return issuer;
  }

  static useFetch() {
    this.httpClient = httpFetch();
  }

  static useGot() {
    this.httpClient = httpGot();
  }

  static useRequest() {
    this.httpClient = httpRequest();
  }

  get httpClient() {
    return this.constructor.httpClient;
  }

  static get httpClient() {
    if (httpClient) {
      return httpClient;
    }

    try {
      if (window.fetch) { // eslint-disable-line no-undef
        this.useFetch();
      }
    } catch (err) {
      this.useGot();
    }

    return httpClient;
  }

  static set httpClient(client) {
    assert.equal(typeof client.get, 'function', 'client.get must be a function');
    assert.equal(typeof client.post, 'function', 'client.post must be a function');
    assert(client.HTTPError, 'client.HTTPError must be a constructor');
    httpClient = client;
  }

  /**
   * @name httpOptions
   * @api public
   */
  httpOptions(...args) {
    return this.constructor.httpOptions(...args);
  }

  /**
   * @name httpOptions
   * @api public
   */
  static httpOptions(values) {
    return _.merge({}, this.defaultHttpOptions, values);
  }

  /**
   * @name defaultHttpOptions
   * @api public
   */
  static get defaultHttpOptions() {
    return defaultHttpOptions;
  }

  /**
   * @name defaultHttpOptions=
   * @api public
   */
  static set defaultHttpOptions(value) {
    defaultHttpOptions = _.merge({}, DEFAULT_HTTP_OPTIONS, value);
  }
}

module.exports = Issuer;
