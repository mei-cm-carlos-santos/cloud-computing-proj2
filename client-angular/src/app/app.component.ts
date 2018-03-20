import { Component , OnInit, OnDestroy } from '@angular/core';
import { Router } from '@angular/router';
import {UserSecurityService} from './services/security.service';
import { WebSocketService } from './services/websocket.service';
import {Subscription} from 'rxjs/Subscription';

@Component({
    moduleId: module.id,
    selector: 'my-app',
    templateUrl: 'app.component.html'
})
export class AppComponent implements OnInit, OnDestroy{  
    private subscriptions: Array<Subscription>;
    private timeoutId : any = null;
    appName = 'TicTacToe'; 
    _lastActiveGameId: string = '';
    lastActiveGameNumber: number = -1;

    get lastActiveGameId():string {
        return this._lastActiveGameId;
    }
    set lastActiveGameId(newId:string) {
        if (this.timeoutId != null) {
            clearTimeout(this.timeoutId);
            this.timeoutId = null;
        }
        let app: AppComponent = this;
        this._lastActiveGameId = newId;
        if (this._lastActiveGameId != "") {
            app.timeoutId = setTimeout(() => {
                app.lastActiveGameId = "";
                clearTimeout(app.timeoutId);
                app.timeoutId = null;
            }, 30000);
        }
    }

  constructor(
      private router:Router, 
      private userSecurity: UserSecurityService,
      private websocketService: WebSocketService) {}

  ngOnInit() {
        this.subscriptions = [];
        this.subscriptions.push(this.websocketService.getGameEnded().subscribe((gameId:any) => this.gameEnded(gameId)));
        this.subscriptions.push(this.websocketService.getLobbyJoinGame().subscribe((obj:any) => this.lobbyJoinGame(obj)));
    }

  ngOnDestroy() {
        this.websocketService.leaveAllGames();
        this.subscriptions.forEach((subscription: Subscription) => {
            subscription.unsubscribe();            
        });
        this.subscriptions = [];
  }  

  lobbyJoinGame(obj: any) {
      if (this.isLogged()){
          if (obj.player1 == this.userSecurity.getUserID()) {
                this.websocketService.enterGame(obj.gameId);
                if (this.router.url != '/games') {
                    this.lastActiveGameId = obj.gameId;
                    this.lastActiveGameNumber = obj.gameNumber;
                }
          }
      }
  }

  gameEnded(gameId: any) {
      this.websocketService.leaveGame(gameId);
  }

  isActiveLink(link:string):boolean {
      return this.router.isActive(link, true);
  }  

  isLogged(){
      return this.userSecurity.isLogged();
  }

  username(){
      return this.userSecurity.getUserName();
  }

  logout(){
      this.lastActiveGameId = "";
      this.lastActiveGameNumber = -1;
      this.userSecurity.logoutUser();
      this.router.navigate(['/']);                        
  }

  showAlert() {
      return this.lastActiveGameId != '';
  }

  gotoGame(gameId: string) {
      this.lastActiveGameId = "";
      this.lastActiveGameNumber = -1;
      this.router.navigate(['/games']);
  }

    
}

