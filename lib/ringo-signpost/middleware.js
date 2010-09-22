/**
 * @fileOverview OAuth1 middleware. To apply authentication to parts of your website
 * add this to your list of middlewares and pass the middlware function an object
 * like showed in the usage example.
 *
 * The middleware takes care of the whole oAuth process in particular it:
 *
 *   * displays a simple sign in page using the provider.name and provider.image
 *   * handles the callback by the provider (no need to add a callback to your url config)
 *
 * Once authorization is finished it redirects back to the originally request path
 * in your app. At this point `req.session.oAuthToken` is set and contains the `accessToken`
 * and `tokenSecret` to be used for oauth1 requests.
 *
 * See ringo/signpost's createRequestSigner for an easy way to use this in combination
 * with ringo's httpclient to make http request to an oauth protected resource.
 *  
 * @usage
 *   oAuthConfig = {
 *       protectedPaths: ['/'],
 *       consumer: {
 *           key: 'XXXXXXX',
 *           secret: 'XXXXXX',
 *           callback: {
 *               host: 'http://localhost:8080',
 *               path: '/oauth/callback/',
 *           }
 *
 *       },
 *       provider: {
 *           name: 'Twitter',
 *           image: 'http://example.com/oauth/provider-signin.png',
 *           urls: {
 *               requestToken: 'http://example.com/oauth/request_token',
 *               accessToken: 'http://example.com/oauth/access_token',
 *               authorize: 'http://example.com/oauth/authorize',
 *           },
 *       }
 *   };
 *
 *   middleware = [
 *       require('ringo-signpost/middleware').middleware(oAuthConfig),
 *   ];
 */

var {Session} = require('ringo/webapp/request');
var signpost = Packages.oauth.signpost;

exports.middleware = function(config) {
    var provider = new signpost.basic.DefaultOAuthProvider(
        config.provider.urls.requestToken,
        config.provider.urls.accessToken,
        config.provider.urls.authorize
    );

    return function (app) {
        return function (req) {
            var path = (req.scriptName + req.pathInfo).replace(/\/+/g, '/');
            var session = new Session(req);
            
            // 2) provider is calling us back?
            if (path.indexOf(config.consumer.callback.path) == 0) {
                print ('Got called back with request token ');
                var servletReq = req.env.servletRequest;
                var xRingoForward = servletReq.getParameter('xRingoForward');
                var tokenSecret = servletReq.getParameter(signpost.OAuth.OAUTH_VERIFIER); 
                // 3) get access token
                print ('Fetching access token ');
                var consumer = session.data.oAuthToken.consumer;
                provider.retrieveAccessToken(consumer, tokenSecret);
                session.data.oAuthToken = {
                    isAuthorized: true,
                    accessToken: consumer.getToken(),
                    tokenSecret: consumer.getTokenSecret(),
                };
                // 4) done redirect to original url
                print ('Redirection back to ' + xRingoForward);
                return {
                    status: 303,
                    headers: {Location: xRingoForward},
                    body: ["See other: " + xRingoForward]
                };
            }
            
            var doAuth = config.protectedPaths.indexOf(path) == 0;
            if (doAuth) {
                print ('Protected path ' + path);
                // user already authorized us?
                // FIXME if if we have access token we need to verify user is
                // logged in by doing call to authorize.
                if (session.data.oAuthToken && session.data.oAuthToken.isAuthorized === true) {
                    return app(req);
                }
                // 1) get request token url
                //new signpost.basic.DefaultOAuthConsumer(config.consumer.key, config.consumer.secret)
                var consumer = new signpost.jetty.JettyOAuthConsumer(config.consumer.key, config.consumer.secret)
                session.data.oAuthToken = {
                    consumer: consumer,
                    isAuthorized: false,
                }
                print("Fetching authorize URL from Twitter...");
                var callbackUrl = [config.consumer.callback.host,
                                   config.consumer.callback.path,
                                   "?",
                                   "xRingoForward=",
                                   path].join('');
                var authUrl = provider.retrieveRequestToken(consumer,callbackUrl);
                return {
                    status: 200,
                    headers: {
                        'Content-Type': 'text/html',
                    },
                    body: [
                        '<html><head><title>Sign in</title></head>',
                        '<body><h1>Sign in with ' + config.provider.name + '</h1>',
                        '<a href="' + authUrl + '">',
                        '<img src="' + config.provider.image + '">',
                        '</a>',
                        '</body></html>'
                    ]
                };
            }
            return app(req);
        }
    }
};
