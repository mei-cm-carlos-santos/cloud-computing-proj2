import { Component , OnInit, OnDestroy} from '@angular/core';

import { WebSocketService } from '../services/websocket.service';
import { UserSecurityService } from '../services/security.service';

import {Subscription} from 'rxjs/Subscription';

export enum GameControlStatus {
    playing,
    ended
}

export class GameInfo {
    public gameId: string;
    public game: any;
    public get gameControlStatus(): GameControlStatus {
        if (this.game.gameStatus < 10) {
            return GameControlStatus.playing;
        }
        else {
            return GameControlStatus.ended;
        }        
    }
}

@Component({
    moduleId: module.id,
    selector: 'games',
    templateUrl: 'games.component.html'
})
export class GamesComponent implements OnInit, OnDestroy{ 
    public games: Array<GameInfo>;
    
    private subscriptions: Array<Subscription>;
    
    constructor(
    private userSecurity: UserSecurityService,
    private websocketService: WebSocketService){
    }
    
    ngOnInit() {
        this.subscriptions = [];
        
        this.subscriptions.push(this.websocketService.getMyListOfGames().subscribe((myGames:any) => this.getListOfMyGames(myGames)));
        
        this.subscriptions.push(this.websocketService.getRefreshGame().subscribe((game:any) => this.refreshGame(game)));
        
        this.subscriptions.push(this.websocketService.getGameInvalidPlay().subscribe((obj:any) => this.invalidPlay(obj)));
        
        this.subscriptions.push(this.websocketService.getGamesListChanged().subscribe((obj:any) => this.gamesListChanged(obj)));
        
        this.refreshActiveGames();        
    }
    
    ngOnDestroy() {
        this.subscriptions.forEach((subscription: Subscription) => {
            subscription.unsubscribe();            
        });
        this.subscriptions = [];
    }  
        
    private getGameInfoById(gameId: string): GameInfo{
        let resultGame : GameInfo = null;
        this.games.forEach(game => {
            if (game.gameId == gameId) {
                resultGame = game;
                return;
            }
        });
        return resultGame;
    }
    
    private deleteInfoGameById(gameId: string): any{
        let toDelete = this.getGameInfoById(gameId);
        if (toDelete) {
            this.games.indexOf(toDelete);
            this.games.splice(this.games.indexOf(toDelete), 1);
        }
    }
    
    private getGameById(gameId: string): any{
        return this.getGameInfoById(gameId).game;
    }
    
    private getGameInfo(g: any): GameInfo{
        return this.getGameInfoById(g.gameId);
    }
    private getGame(g: any): any{
        return this.getGameInfo(g).game;
    }
    
    // getGame and replace its content
    private getSetGameInfo(g: any): GameInfo{
        let resultGame : GameInfo = null;
        this.games.forEach(game => {
            if (game.gameId == g.gameId) {
                game.game = g;
                resultGame = game;
                return;
            }
        });
        return resultGame;
    }
    private getSetGame(g: any): any{
        return this.getSetGameInfo(g).game;
    }
    
    
    private buildGames(games: Array<any>){
        let component: GamesComponent = this;
        this.games = [];
        games.forEach(game => {
            let gameInfo = new GameInfo();
            gameInfo.gameId = game.gameId;
            gameInfo.game = game;
            component.games.push(gameInfo);
        });
    }
    
    // ---------------------------------------------------------------------------------
    // Server Message Handlers:
    // ---------------------------------------------------------------------------------    
    gamesListChanged(obj: any) {
        if (this.userSecurity.isLogged()){
            if ( (obj.player1 == this.userSecurity.getUserID()) ||
                 (obj.player2 == this.userSecurity.getUserID())) {
                this.refreshActiveGames();
            }
        }
    }

    getListOfMyGames(myGames: Array<any>) {
        this.buildGames(myGames);
    };
    
    refreshGame(game: any) {
        let g = this.getSetGameInfo(game);
    }
    
    invalidPlay(obj: any) {
        let g = this.getSetGameInfo(obj.game);
    }
    
    // ---------------------------------------------------------------------------------
    // Send Messages to Server
    // ---------------------------------------------------------------------------------    
    
    identifyMyself(){
        this.websocketService.identifyMyself();
    }
    
    refreshActiveGames() {
        this.identifyMyself();
        this.websocketService.myActiveGames();
    }
    
    quitGame(gameId: string) {
        this.websocketService.quitGame(gameId);
    }
    
    clickPeca(eventObj: any) {
        // Only sends message to the server if game has not ended
        if (this.getGameById(eventObj.gameId).gameStatus < 5) {
            this.websocketService.playGame(eventObj.gameId, eventObj.position);
        }
    }
    
    clickClose(eventObj: any) {
        if (eventObj.operation == 'quit') {
            this.websocketService.quitGame(eventObj.gameId);
        } 
        else {
            if (eventObj.operation == 'hide') {
                this.deleteInfoGameById(eventObj.gameId);
            }
        }
    }    
}
