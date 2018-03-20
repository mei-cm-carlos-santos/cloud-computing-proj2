const path = require('path');
const assert = require('assert');
const restify = require('restify');
const passport = require('passport');

import {AppConfig} from './app/app.config';
import {MongoDB} from './db/mongodb';
import {WebSocketServer} from './websockets/wsServer';
import {RestAPI_v1} from './restAPI/restAPI.v1';
import {PassportSecurity} from './security/passport.security';


// Create Restify and WebSocket Server
const restifyServer = restify.createServer();
const socketServer = new WebSocketServer();

// Prepare and configure Restify Server
//restify.CORS.ALLOW_HEADERS.push("content-type");

restifyServer.use(restify.bodyParser());
restifyServer.use(restify.queryParser());
restifyServer.use(restify.fullResponse());

// ----------------------------------------------------------------------------------
// Workaround to solve CORS problems with requests that require Authorization (tokens)
function corsHandler(req, res, next) {
    res.setHeader('Access-Control-Allow-Origin',  '*');
    res.setHeader('Access-Control-Allow-Headers', 'Origin, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, X-Response-Time, X-PINGOTHER, X-CSRF-Token, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Expose-Headers', 'X-Api-Version, X-Request-Id, X-Response-Time');
    res.setHeader('Access-Control-Max-Age', '1000');    
    return next();
}

function optionsRoute(req, res, next) {
    res.send(200);
    return next();
}

restifyServer.on( "MethodNotAllowed", function( request, response )
{
    if ( request.method.toUpperCase() === "OPTIONS" )
    {
        // Send the CORS headers
        //
        response.header( "Access-Control-Allow-Credentials", true                                    );
        response.header( "Access-Control-Allow-Headers",     restify.CORS.ALLOW_HEADERS.join( ", " ) );
        response.header( "Access-Control-Allow-Methods",     "GET, POST, PUT, DELETE, OPTIONS"       );
        response.header( "Access-Control-Allow-Origin",      request.headers.origin                  );
        response.header( "Access-Control-Max-Age",           0                                       );
        response.header( "Content-type",                     "text/plain charset=UTF-8"              );
        response.header( "Content-length",                   0                                       );

        response.send( 204 );
    }
    else
    {
        response.send( new restify.MethodNotAllowedError() );
    }
} );





restifyServer.opts('/\.*/', corsHandler, optionsRoute);

// End of Workaround
// ----------------------------------------------------------------------------------

// Original code (without Workaround)
/*
restifyServer.use(restify.CORS({
    credentials: true,
}));
*/

// Mongo configuration
let mongo = new MongoDB(AppConfig.mongoDB);

// Passport configuration
const passportSecurity = new PassportSecurity(restifyServer, mongo);

// Register all RespAPI endpoints
new RestAPI_v1(restifyServer, mongo, socketServer, passportSecurity);

mongo.db.on('error', console.error.bind(console, 'connection error:'));

mongo.db.on('open', function() {
    //Check if User Collection exists 
    restifyServer.listen(AppConfig.restAPIPort, () => console.log('%s listening at %s', restifyServer.name, restifyServer.url));
    // Websocket is initialized after the server
    socketServer.init(restifyServer.server, mongo);
});

