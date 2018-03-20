const mongoose = require('mongoose');


export let userSchema = mongoose.Schema({
    username: String,
    name: String,
    email: String,
    totalGames: Number,
    totalVictories: Number
});

/*
 Follwing schema only used on MEAN full stack solution:
*/ 
/*
export let userSchema = mongoose.Schema({
    username: String,
    passwordHash: String,
    name: String,
    email: String,
    totalGames: Number,
    totalVictories: Number
});
*/

export let gameSchema = mongoose.Schema({
    gameId: { type: Number },
    status: String,  //P-Pending; A-Active Gamming; T-Terminated; C-Canceled on lobby; TIMEOUT-Timeout Occorred 
    player1: {type: mongoose.Schema.Types.ObjectId, ref: 'User'}, // also, the player that created the game
    player2: {type: mongoose.Schema.Types.ObjectId, ref: 'User'},
    winner: {type: mongoose.Schema.Types.ObjectId, ref: 'User'},  //null if tied
    createdTime: Date,
    startedTime: Date,
    terminatedTime: Date,
    gameState: String // The complete game state in JSON    
});


