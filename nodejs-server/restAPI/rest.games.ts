import {RestBase} from './rest.base';
import {HandlerSettings} from '../app/handler.settings';
import {MongoDB} from '../db/mongodb';

export class RestGames extends RestBase{
    constructor(handlerSettings: HandlerSettings){
        super(handlerSettings);
    }
    
    private updateExcessiveLobbyGames(games: any[], mantainLimit: number){
        let i = 0;
        games.forEach(element => {
            i++;
            if (i > mantainLimit) {
                this.handlerSettings.mongoDB.Game
                .findById(element._id)
                .then(gameFromDB => {
                    if (gameFromDB !== null) {
                        gameFromDB.status = 'C';
                        gameFromDB.save();
                    }
                });
            }
        });
    }
    
    public lobby = (request: any, response: any, next: any) => {      
        this.mongoDB.Game
        .find({status: 'P'})
        .sort({createdTime:-1})
        .limit(35)
        .select('gameId createdTime player1')
        .populate('player1', 'username name email')
        .then(games => {
            // Se total jogos no lobby >= 30, cancela todos os que são mais antigos 
            // Mantendo apenas 20 ativos
            if (games.length >= 30) {
                this.updateExcessiveLobbyGames(games,20);
            }
            games = games.slice(0,20);
            response.json(games || []);
            next();
        }).catch(function(err){
            console.error(err);
        });
    }
    
    public history = (request: any, response: any, next: any) => {
        var ObjectId = require('mongoose').Types.ObjectId; 
        let invalidParam = false;
        let historyType = "";
        if (request.params.t != null){
            historyType = request.params.t;
        };
        if ((historyType != 'mg') && (historyType != 'mv') && (historyType != 'md') && (historyType != 'g')) {
            console.error('RestGames.history: Invalid parameter t');
            response.send(400, {'msg': 'Invalid parameter'} || {});
            return next();
        }        
        let userID = request.user.userID;
        
        switch (historyType) {
            // Todos os jogos que terminaram e que um determinado user jogou
            // { "status": "T", $and: [ { $or: [ { "player1": ObjectId("589e09b9c9e9c62b8cc092ae") }, { "player2": ObjectId("589e09b9c9e9c62b8cc092ae") } ] } ] }
            case 'mg':
            this.mongoDB.Game
            .find(
            { "status": "T", 
            $and: 
            [ 
            { $or:  [ 
                { "player1": new ObjectId(userID) }, 
                { "player2": new ObjectId(userID) } 
                ] 
            } 
            ] 
        }
        )
        .sort({terminatedTime:-1})
        .limit(50)
        .select('gameId startedTime terminatedTime player1 player2 winner')
        .populate('player1')
        .populate('player2')
        .populate('winner')
        .then(games => {
            response.json(games || []);
            next();
        }).catch(function(err){
            console.error(err);
        });
        break;    
        // Todos os jogos que terminaram e que um determinado user ganhou
        // { "status": "T", $and: [ { "winner": ObjectId("589e09b9c9e9c62b8cc092ae") } ] }
        case 'mv':
        this.mongoDB.Game
        .find(
        { "status": "T", 
        $and: 
        [ 
        { 
            "winner": new ObjectId(userID) 
        }
        ]
    }
    )
    .sort({terminatedTime:-1})
    .limit(50)
    .select('gameId startedTime terminatedTime player1 player2 winner')
    .populate('player1')
    .populate('player2')
    .populate('winner')
    .then(games => {
        response.json(games || []);
        next();
    }).catch(function(err){
        console.error(err);
    });
    break;  
    // Todos os jogos que terminaram e que um determinado user perdeu            
    //{ "status": "T", $and: [ { "winner": { $ne: ObjectId("589e09b9c9e9c62b8cc092ae") } }, { $or: [ { "player1": ObjectId("589e09b9c9e9c62b8cc092ae") }, { "player2": ObjectId("589e09b9c9e9c62b8cc092ae") } ] } ] }
    case 'md':
    this.mongoDB.Game
    .find(
    { "status": "T", 
    $and: 
    [ 
    { "winner": { $ne: new ObjectId(userID) } },
    { $or:  [ 
        { "player1": new ObjectId(userID) }, 
        { "player2": new ObjectId(userID) } 
        ] 
    } 
    ] 
}
)
.sort({terminatedTime:-1})
.limit(50)
.select('gameId startedTime terminatedTime player1 player2 winner')
.populate('player1')
.populate('player2')
.populate('winner')
.then(games => {
    response.json(games || []);
    next();
}).catch(function(err){
    console.error(err);
});
break;    
case 'g':
this.mongoDB.Game
.find(
{status: 'T'}
)
.sort({terminatedTime:-1})
.limit(50)
.select('gameId startedTime terminatedTime player1 player2 winner')
.populate('player1')
.populate('player2')
.populate('winner')
.then(games => {
    response.json(games || []);
    next();
}).catch(function(err){
    console.error(err);
});
break;                
}  
}

public createGame = (request: any, response: any, next: any) => {
    let thisObj : RestGames = this;
    let userID = request.user.userID;
    
    let newGame = new this.mongoDB.Game();
    newGame.status = 'P';   //P-Pending; A-Active Gamming; T-Terminated; C-Canceled 
    newGame.player1 = userID;
    newGame.player2 = null;
    newGame.winner = null;
    newGame.createdTime = new Date(),
    newGame.startedTime = null;
    newGame.terminatedTime = null;
    newGame.save().then(function (createdGame) {
        response.send(200, createdGame || {});       
        
        // notify All users that a new game was created
        if (thisObj.handlerSettings.wsServer) {
            let objToSend = {
                'gameId': createdGame._id,
                'gameNumber': createdGame.gameId,
                'player1' : createdGame.player1,
                'player2' : createdGame.player2,
            };
            thisObj.handlerSettings.wsServer.notifyAll('lobbyChanged', objToSend);
        }                
        next();
    }).catch(function(err){
        console.error(err);
        next();
    });        
}

public joinGame = (request: any, response: any, next: any) => {
    let thisObj : RestGames = this;
    
    if (request.params.id == null){
        console.error('RestGames.joinGame: Invalid parameters');
        response.send(400, {'msg': 'Invalid parameters'} || {});
        return next();
    }        
    let gameId = request.params.id;
    let userID = request.user.userID;
    
    this.mongoDB.Game
    .findById(gameId)
    .then(game => {
        if (game === null) {
            response.send(401, 'Unauthorized');
            next();
        } 
        else {
            game.status = 'A';
            game.player2 = userID;
            game.save().then(function (updatedGame) {
                response.send(200, updatedGame || {});
                
                // notify All users that someone has joined a game
                if (thisObj.handlerSettings.wsServer) {
                    let objToSend = {
                        'gameId': updatedGame._id,
                        'gameNumber': updatedGame.gameId,
                        'player1' : updatedGame.player1,
                        'player2' : updatedGame.player2,
                    };
                    thisObj.handlerSettings.wsServer.notifyAll('lobby_joinGame', objToSend);
                    thisObj.handlerSettings.wsServer.notifyAll('lobbyChanged', objToSend);
                    thisObj.handlerSettings.wsServer.notifyAll('gamesPlayingChanged', objToSend); 
                }                                                                
                next();
            }).catch(function(err){
                console.error(err);
                next();
            });
        }
    }).catch(function(err){
        console.error(err);
        response.send(401, 'Unauthorized');
        next();
    });
}    

public removeGame = (request: any, response: any, next: any) => {
    let thisObj : RestGames = this;
    if (request.params.id == null){
        console.error('RestGames.joinGame: Invalid parameters');
        response.send(400, {'msg': 'Invalid parameters'} || {});
        return next();
    }        
    let gameId = request.params.id;
    let userID = request.user.userID;
    this.mongoDB.Game
    .findById(gameId)
    .then(game => {
        if (game === null) {
            response.send(401, 'Unauthorized');
            next();
        } 
        else {
            if (game.player1 != userID) {
                response.send(401, 'Unauthorized');
                next();                        
            }
            else {
                game.status = 'C';
                game.save().then(function (updatedGame) {
                    response.send(200, updatedGame || {});       
                    
                    // notify All users that someone has removed a game
                    if (thisObj.handlerSettings.wsServer) {
                        let objToSend = {
                            'gameId': updatedGame._id,
                            'gameNumber': updatedGame.gameId,
                            'player1' : updatedGame.player1,
                            'player2' : updatedGame.player2,
                        };
                        thisObj.handlerSettings.wsServer.notifyAll('lobbyChanged', objToSend);
                    }                
                    next();
                }).catch(function(err){
                    console.error(err);
                    next();
                });
            }
        }
    }).catch(function(err){
        console.error(err);
        response.send(401, 'Unauthorized');
        next();
    });
}    

}
