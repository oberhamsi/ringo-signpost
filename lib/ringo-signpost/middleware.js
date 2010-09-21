/**
 * @fileOverview OAuth middleware. 
 */

var strings = require('ringo/utils/strings');
var base64 = require('ringo/base64');
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
                // twitter says I should use headers but doesn't set them :|
                // http://dev.twitter.com/pages/auth
                print ('Got called back with request token ');
                var servletReq = req.env.servletRequest;
                var xRingoForward = servletReq.getParameter('xRingoForward');
                var tokenSecret = servletReq.getParameter(signpost.OAuth.OAUTH_VERIFIER); 
                // 3) get access token
                print ('Fetching access token ');
                provider.retrieveAccessToken(session.data.oAuth.consumer, tokenSecret);
                // FIXME error handling if user denied
                session.data.oAuth.isAuthorized = true;
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
                if (session.data.oAuth && session.data.oAuth.isAuthorized === true) {
                    return app(req);
                }
                // 1) get request token url
                //new signpost.basic.DefaultOAuthConsumer(config.consumer.key, config.consumer.secret)
                var consumer = new signpost.jetty.JettyOAuthConsumer(config.consumer.key, config.consumer.secret)
                session.data.oAuth = {
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
