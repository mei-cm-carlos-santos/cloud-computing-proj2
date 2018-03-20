import {HandlerSettings} from '../app/handler.settings';
import {AppConfig} from '../app/app.config';
import {WebSocketServer} from '../websockets/wsServer';
import {PassportSecurity} from '../security/passport.security';
import {MongoDB} from '../db/mongodb';

import {RestUsers} from './rest.users';
import {RestGames} from './rest.games';
import {RestAuth} from './rest.auth';

export class RestAPI_v1{

    private handlerSettings: HandlerSettings = null;
    private users: RestUsers;
    private games: RestGames;
    private auth: RestAuth;

    private url = (mainUrl: string) => this.handlerSettings.prefix + mainUrl;
    
    constructor (server: any, mongoDB: MongoDB, wsServer: WebSocketServer, passSecurity: PassportSecurity) {
        this.handlerSettings = new HandlerSettings(mongoDB, wsServer, passSecurity, AppConfig.restAPIPrefix('1'));
        this.users= new RestUsers(this.handlerSettings);
        this.games= new RestGames(this.handlerSettings);
        this.auth= new RestAuth(this.handlerSettings);

        // Configure all endpoints - may use several Rest.Modules


        // Auth Related:
        server.post(this.url('preregister'), this.auth.preRegisterUser);
/*
 Follwing methods are only used on MEAN full stack solution:
*/ 
/*
        server.post(this.url('authenticate'), this.auth.authenticate);
        server.post(this.url('register'), this.auth.registerUser);
        server.put(this.url('changepassword'), this.handlerSettings.security.authorize, this.auth.changePassword);
        server.post(this.url('uniqueusername'), this.auth.checkUniqueUsername);
        server.post(this.url('uniqueemail'), this.auth.checkUniqueEmail);
*/
        // Users Related:
        server.put(this.url('user/myuser'), this.handlerSettings.security.authorize, this.users.updateMyUser);
        server.get(this.url('users/topten'), this.users.topten);
        
        //server.del(this.url('destroyusers'), this.users.destroyAllUsers);
        
        // Lobby related
        server.get(this.url('games/lobby'), this.handlerSettings.security.authorize, this.games.lobby);
        server.get(this.url('games/history/:t'), this.handlerSettings.security.authorize, this.games.history);
        server.post(this.url('games'), this.handlerSettings.security.authorize, this.games.createGame);
        server.post(this.url('games/join'), this.handlerSettings.security.authorize, this.games.joinGame);
        server.post(this.url('games/remove'), this.handlerSettings.security.authorize, this.games.removeGame);

        console.log("RestAPI v1 routes registered");
    };
}