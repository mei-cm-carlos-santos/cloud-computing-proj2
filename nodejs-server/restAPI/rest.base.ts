import {HandlerSettings} from '../app/handler.settings';
import {WebSocketServer } from '../websockets/wsServer';
import {MongoDB} from '../db/mongodb';

export class RestBase{

    public handlerSettings: HandlerSettings;
    public mongoDB: MongoDB;
    public wsServer: WebSocketServer;

    protected handleError = (err: string, response: any, next: any) => {
    	response.send(500, err);
	    next();
    }

    constructor(handlerSettings: HandlerSettings){
        this.handlerSettings = handlerSettings;
        this.mongoDB = this.handlerSettings.mongoDB;
        this.wsServer = this.handlerSettings.wsServer;
    }
}
