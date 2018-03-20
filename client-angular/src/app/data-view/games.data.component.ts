import { Component, OnInit, OnDestroy } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import {RestGameService} from '../services/rest.game.service';
import {UserSecurityService} from '../services/security.service';

@Component({
    moduleId: module.id,
    selector: 'gamesdata',
    templateUrl: 'games.data.component.html'
})
export class GamesDataComponent implements OnInit, OnDestroy{
    public games: Array<any> = [];
    public errorMessage: string;

    private historytype: string;

    private sub: any;

    constructor (
        private restGameService: RestGameService,
        private userSecurity: UserSecurityService,
        private route: ActivatedRoute){} 

    ngOnInit(){
        this.historytype = "";
        this.sub = this.route.params.subscribe(params => {
            this.historytype = params['t']; 
            this.fillGames();
        });        
    }

    ngOnDestroy() {
         this.sub.unsubscribe();
    }

    fillGames() {
        if ((this.historytype == 'mg') || (this.historytype == 'mv') || (this.historytype == 'md') || (this.historytype == 'g')) {
            this.restGameService.history(this.historytype)
                    .subscribe(
                        games => this.games = games,
                        error =>  this.errorMessage = error);
        }
        else {
            this.games = [];
        }
    }

    errorMessageExists() {
        return this.errorMessage != "";
    }

    historyTypeDescription() {
        switch (this.historytype) {
            case 'g':
                return 'All games (last 50)';
            case 'mg':
                return 'My games  (last 50)';
            case 'mv':
                return 'My victories (last 50)';
            case 'md':
                return 'My defeats or ties (last 50)';
            default:
                return '';
        }
    }

    getDuration(terminatedTime : any, startedTime: any) {
        let eventStartTime = new Date(startedTime);
        let eventEndTime = new Date(terminatedTime);
        // Returns the number of seconds
        return (eventEndTime.getTime() - eventStartTime.getTime()) / 1000;
    }

    winnerClass(game: any, playerNumber: number) {
/*        if ((this.historytype == 'mv') || (this.historytype == 'md')) {
            return false;
        }
*/
        if (game.winner == undefined) {
            return false;
        }
        if ((playerNumber==1) && (game.player1._id == game.winner._id)) {
            return true;
        } 
        if ((playerNumber==2) && (game.player2._id == game.winner._id)) {
            return true;
        }
        return false;
    }
}