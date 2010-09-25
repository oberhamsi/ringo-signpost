/** 
 * @fileOverview
 * Wrapper around Signpost <http://github.com/kaeppler/signpost.git>. Tuned for three legged oauth.
 *
 *
 */
 
var signpost = Packages.oauth.signpost;
var {Request} = require('ringo/webapp/request');


/** 
 * Creates a new signpost.jetty.JettyOAuthConsumer for signing jetty7 requests.
 * @param {Object} consumer must contain `key` and `secret`.
 */
exports.JettyConsumer = function(opts) {
    if (!opts.key || !opts.secret) {
        throw new Error('Consumer key or secret missing');
    }
    return new signpost.jetty.JettyOAuthConsumer(opts.key, opts.secret);
};

/** 
 * Creates a new signpost.basic.DefaultOAuthConsumer for signing java.net.HttpURLConnection requests.
 * @param {Object} consumer must contain `key` and `secret`.
 */
exports.Consumer = function(opts) {
    if (!opts.key || !opts.secret) {
        throw new Error('Consumer key or secret missing');
    }
    return new signpost.basic.DefaultOAuthConsumer(opts.key, opts.secret);
};

/**
 * OAuth 1.0a Provider.
 * @param {Object} opts must contain callback object {host, path} and urls {requestToken, accessToken, authorize}
 *
 *
 * @example
 * // keep the provider around. we can re-use him for different consumers. threadsafe.
 * var signpost = require('ringo/signpost');
 * var provider = new signpost.Provider({
 *                  urls: {requestToken, accessToken, authorize},
 *                  callback: {path, host}
 *                });
 * var consumer = new signpost.HttpClientConsumer({key, secret});
 * 
 * // this is the url the user must visit to authorize you.
 * // (optionally pass the protected path to redirect to it post authorization)
 * var signInUrl = provider.retrieveSignInUrl(consumer, protectedPath);
 * 
 * // the provider calls you back: pass the consumer object as well as
 * // the callback request to finally get the accessTokens.
 * var accessToken = provier.retrieveAccessToken(consumer, req);
 *
 * // optionally: get the originally requested protected path
 * var path = provider.getProtectedPath(req);
 *
 *
 *   * the methods prefixed `retrieve*` do http requests to the provider.
 *   * `get*` methods are local.
 *
 */
var Provider = exports.Provider = function(opts) {
    if (!opts || !opts.urls || !opts.urls.requestToken || !opts.urls.accessToken || !opts.urls.authorize) {
        throw new Error('Missing provider url option(s). {urls:{requestToken, accessToken, authorize}}');
    }
    if (!opts.callback.host || !opts.callback.path) {
        throw new Error('Missing callback option(s). {callback: {host, path}}');
    }
    
    /** 
     * @param {String} path
     * @returns {Boolean} true if the passed path starts with the configured callback.path
     */
    this.isCallbackPath = function(path) {
        return path.indexOf(opts.callback.path) == 0;
    };
    
    /** 
     * Given a consumer and the request object of provider's callback.
     * @param {ringo.signpost.Consumer} consumer
     * @param {ringo.webapp.request.Request} request object (can also be a org.ringojs.jsgi.JsgiRequest)
     * @returns {Object} with `accessToken` and `tokenSecret` properties.
     */
    this.retrieveAccessToken = function(consumer, request) {
        var tokenSecret = null;
        if (request instanceof Request) {
            tokenSecret = request.params[signpost.OAuth.OAUTH_VERIFIER];
        } else {
            var servletReq = request.env.servletRequest;
            tokenSecret = servletReq.getParameter(signpost.OAuth.OAUTH_VERIFIER);         
        }
        if (tokenSecret === null) {
            throw new Error('Request does not contain token secret');
        }
        provider.retrieveAccessToken(consumer, tokenSecret);
        return {
            accessToken: consumer.getToken(),
            tokenSecret: consumer.getTokenSecret(),
        }
    };
    
    /** 
     * @param {ringo.signpost.Consumer} consumer
     * @param {String} path requested path that triggered this auth (optional. for redirect post auth.)
     * @see #getProtectedPath
     */
    this.retrieveSignInUrl = function(consumer, path) {
        return provider.retrieveRequestToken(consumer, getCallbackUrl(path));
    };
    
    /** 
     * @param {ringo.webapp.request.Request} request object of provider's callback (can also be a org.ringojs.jsgi.JsgiRequest)
     */
    this.getProtectedPath = function(request) {
        if (request instanceof Request) {
            return request.getHeader(Provider.REDIRECT_HEADER);
        } else {
            var servletReq = request.env.servletRequest;
            return servletReq.getParameter(Provider.REDIRECT_HEADER);
        }
    };
    
    /** 
     * constructs callback url
     */
    function getCallbackUrl(path) {
        return [opts.callback.host,
                opts.callback.path,
                "?",
                Provider.REDIRECT_HEADER,
                "=",
                path
                ].join("");
    };
    
    var provider = new signpost.basic.DefaultOAuthProvider(
        opts.urls.requestToken,
        opts.urls.accessToken,
        opts.urls.authorize
    );
    
    return this;
};

/**
 * @ignore
 */
Provider.REDIRECT_HEADER = 'xRingoOAuthForward';
