const mongoose = require("mongoose");

import { autoIncrement } from 'mongoose-plugin-autoinc';

import {userSchema, gameSchema} from './db.schema';

export class MongoDB{
    public db : any;
    public User : any;
    public Game : any;

    constructor (uri: string) {
        //this.conn = mongoose.createConnection(uri, { promiseLibrary: require('bluebird') });

        mongoose.Promise = require('bluebird');

        this.db = mongoose.createConnection(uri);


        gameSchema.plugin(autoIncrement, {
            model: 'Game',
            field: 'gameId'
        }); 

        this.User = this.db.model('User', userSchema);
        this.Game = this.db.model('Game', gameSchema);

    }
}
