const passport = require('passport');
const BearerStrategy = require('passport-http-bearer').Strategy;

import {MongoDB} from '../db/mongodb';
import {AuthUtil, UserInfo} from './auth.util';

export class PassportSecurity {
    public passport = null;
    public authorize = null;  
    private mongo: MongoDB;

    constructor (server: any, mongo: MongoDB) {
        this.passport = passport;
        this.mongo = mongo;
        // Init Middleware
        this.initMiddleware(server);
        this.authorize = this.passport.authenticate('bearer', { session: false });      
    }

    public initMiddleware = (server : any) => {
        server.use(passport.initialize());

        passport.use(new BearerStrategy((token, done) => {
            let user: UserInfo = AuthUtil.validateToken(token);
            if (user){
                return done(null, user, { scope: 'all' })
            } else {
                return done(null, false);
            }
        }));
    } 
}  