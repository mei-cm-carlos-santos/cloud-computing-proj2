import { Component, Input, Output, EventEmitter } from '@angular/core';
import { GameInfo, GameControlStatus } from './games.component';
import { UserSecurityService }    from '../services/security.service'


enum GameStatus {
            turnPlayer1 = 1,
            turnPlayer2 = 2,
            endedTie = 10,
            endedWonPlayer1 = 11,
            endedWonPlayer2 = 12,
            canceledByPlayer1 = 21,
            canceledByPlayer2 = 22,
            timeout = 30
        }

@Component({
    moduleId: module.id,
    selector: 'game',
    templateUrl: 'game.component.html'
})
export class GameComponent { 
    @Input()
    public gameInfo: GameInfo;

    @Output() 
    onClickPeca = new EventEmitter<any>(false);

    @Output() 
    onClickClose = new EventEmitter<any>(false);

    constructor(private userSecurity: UserSecurityService) {}

    pecaImageURL = (peca: number):string => {
        let imgSrc = String(peca);
        if (peca > 0) {
            if (peca == this.currentPlayerNumber()) {
                imgSrc += '-b';
            }
            else {
                imgSrc += '-c';
            }
        }
        return 'assets/img/' + imgSrc + '.png';
    }

    currentPlayerNumber = () => {
        if (this.userSecurity.getUserID() == this.gameInfo.game.player1) {
            return 1;
        }
        if (this.userSecurity.getUserID() == this.gameInfo.game.player2) {
            return 2;
        }
        return 0;    
    }

    nameOfPlayer = (numberOfPlayer: number) => {
        if (this.currentPlayerNumber() == numberOfPlayer) {
            if (numberOfPlayer == 1) {
                return this.gameInfo.game.player1Name + " (You)";
            } 
            else {
                return this.gameInfo.game.player2Name + " (You)";
            }
        }
        else  {
            if (numberOfPlayer == 1) {
                return this.gameInfo.game.player1Name;
            } 
            else {
                return this.gameInfo.game.player2Name;
            }
        }
    }

    clickPeca = (position: number) => {
        this.onClickPeca.emit({'gameId': this.gameInfo.gameId, 'position': position});
    }

    clickClose = () => {
        if (this.gameEnded()) {
            this.onClickClose.emit({'gameId': this.gameInfo.gameId, 'operation': 'hide'});            
        } 
        else {
            this.onClickClose.emit({'gameId': this.gameInfo.gameId, 'operation': 'quit'});            
        }
    }

    gameEnded = () => {
        return this.gameInfo.gameControlStatus == GameControlStatus.ended;
    }

    submitText = (): string => {
        if (this.gameEnded()) {
            return "Hide game";
        } 
        else {
            return "Quit game";
        }
    }    

    submitClass = (): string => {
        if (this.gameEnded()) {
            return "btn-info";
        } 
        else {
            return "btn-danger";
        }
    }    

    alertClass = (): string => {
        switch (this.gameInfo.game.gameStatus as GameStatus) {
            case GameStatus.turnPlayer1:
                if (this.currentPlayerNumber() == 1) {
                    return "alert-info";                    
                }
                else {
                    return "alert-warning";
                }
            case GameStatus.turnPlayer2:
                if (this.currentPlayerNumber() == 2) {
                    return "alert-info";                    
                }
                else {
                    return "alert-warning";
                }
            case GameStatus.endedTie:
                    return "alert-warning";
            case GameStatus.endedWonPlayer1:
                if (this.currentPlayerNumber() == 1) {
                    return "alert-success";                    
                }
                else {
                    return "alert-danger";
                }
            case GameStatus.endedWonPlayer2:
                if (this.currentPlayerNumber() == 2) {
                    return "alert-success";                    
                }
                else {
                    return "alert-danger";
                }
            case GameStatus.canceledByPlayer1:
                if (this.currentPlayerNumber() == 1) {
                    return "alert-danger";                    
                }
                else {
                    return "alert-warning";
                }
            case GameStatus.canceledByPlayer2:
                if (this.currentPlayerNumber() == 2) {
                    return "alert-danger";                    
                }
                else {
                    return "alert-warning";
                }
            case GameStatus.timeout:
                return "alert-danger";
        }
    }

    alertText = (): string => {
        switch (this.gameInfo.game.gameStatus as GameStatus) {
            case GameStatus.turnPlayer1:
                if (this.currentPlayerNumber() == 1) {
                    return "It's your Turn.";                    
                }
                else {
                    return "It's your opponent's turn.";
                }
            case GameStatus.turnPlayer2:
                if (this.currentPlayerNumber() == 2) {
                    return "It's your Turn.";                    
                }
                else {
                    return "It's your opponent's turn.";
                }
            case GameStatus.endedTie:
                    return "Game has ended. There was a tie!";
            case GameStatus.endedWonPlayer1:
                if (this.currentPlayerNumber() == 1) {
                    return "Game has ended. You Win!";                    
                }
                else {
                    return "Game has ended. You Lost!";
                }
            case GameStatus.endedWonPlayer2:
                if (this.currentPlayerNumber() == 2) {
                    return "Game has ended. You Win!";                    
                }
                else {
                    return "Game has ended. You Lost!";
                }
            case GameStatus.canceledByPlayer1:
                if (this.currentPlayerNumber() == 1) {
                    return "Game was canceled by you!";                    
                }
                else {
                    return "Game was canceled by your opponent!";                    
                }
            case GameStatus.canceledByPlayer2:
                if (this.currentPlayerNumber() == 2) {
                    return "Game was canceled by you!";                    
                }
                else {
                    return "Game was canceled by your opponent!";                    
                }
            case GameStatus.timeout:
                return "Game was terminated due to a timeout!";                   
        }
    }
}