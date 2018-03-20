import { Component, OnInit, OnDestroy} from '@angular/core';
import {RestGameService} from '../services/rest.game.service';
import {UserSecurityService} from '../services/security.service';
import { WebSocketService } from '../services/websocket.service';
import { Router } from '@angular/router';
import {Subscription} from 'rxjs/Subscription';


@Component({
    moduleId: module.id,
    selector: 'lobby',
    templateUrl: 'lobby.component.html'
})
export class LobbyComponent implements OnInit, OnDestroy { 
    public games: Array<any> = [];
    public errorMessage: string;
    private subscriptions: Array<Subscription>;

    constructor (
        private router:Router, 
        private restGameService: RestGameService,
        private userSecurity: UserSecurityService,
        private websocketService: WebSocketService
        ){ } 

    ngOnInit(){ 
        this.errorMessage = "";
        this.fillGames();
        this.subscriptions = [];
        this.subscriptions.push(this.websocketService.getLobbyChanged().subscribe((obj:any) => this.lobbyChanged(obj)));
    }

  ngOnDestroy() {
        this.subscriptions.forEach((subscription: Subscription) => {
            subscription.unsubscribe();            
        });
        this.subscriptions = [];
  }  
    
    // WebServer notifications from server
    lobbyChanged(obj: any) {
        this.fillGames();
    }

    fillGames() {
        this.restGameService.lobby()
                .subscribe(
                     games  => this.games = games,
                     error =>  this.errorMessage = error);
    }
    
    createGame(){
        this.errorMessage = "";
        let component: LobbyComponent = this;
        this.restGameService.createGame()
                .subscribe(
                    createdGame  => {
                        component.fillGames();
                        },
                    error => {
                        component.errorMessage = "There was an error creating the game";
                }); 
    }

    createdByMe(createdBy: string){
        return createdBy == this.userSecurity.getUserID();
    }

    joinGame(gameId: string){
        this.errorMessage = "";
        let component: LobbyComponent = this;
        this.restGameService.joinGame(gameId)
                .subscribe(
                    updatedGame  => {
                        this.websocketService.enterGame(gameId);                        
                        this.router.navigate(['/games'])
                        //component.fillGames();
                        },
                    error => {
                        component.errorMessage = "There was an error joining the game";
                }); 
    }

    removeGame(gameId: string){
        this.errorMessage = "";
        let component: LobbyComponent = this;
        this.restGameService.removeGame(gameId)
                .subscribe(
                    updatedGame  => {
                        component.fillGames();
                        },
                    error => {
                        component.errorMessage = "There was an error removing the game";
                }); 
    }
    
}