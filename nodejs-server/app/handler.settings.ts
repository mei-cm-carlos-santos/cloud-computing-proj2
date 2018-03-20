import {WebSocketServer } from '../websockets/wsServer';
import {MongoDB} from '../db/mongodb';

export class HandlerSettings {
    public mongoDB: MongoDB = null;
    public wsServer: WebSocketServer = null;
    public security: any = null;
    public prefix: string = '';

    constructor (mongoDB: MongoDB, wsServer: WebSocketServer, security: any, prefix: string) {
        this.mongoDB = mongoDB;
        this.wsServer = wsServer;
        this.security = security;
        this.prefix = prefix;
    } 
}