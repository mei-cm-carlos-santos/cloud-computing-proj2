
export enum GameStatus {
    turnPlayer1 = 1,
    turnPlayer2 = 2,
    endedTie = 10,
    endedWonPlayer1 = 11,
    endedWonPlayer2 = 12,
    canceledByPlayer1 = 21,
    canceledByPlayer2 = 22,
    timeout = 30
}

// TODO - Change Timeout of the game
export const TIMEOUT = 20*60*1000; // Game Timeout in miliSeconds (20 minutos)

class GameEngineError extends Error {
    constructor(m: string) {
        super(m);
        // Set the prototype explicitly.
        //Object.setPrototypeOf(this, GameEngineError.prototype);
    }
}

export class TicTacToeGame {
    public gameId: string;
    // 0 - Not played yet
    // 1 - Player 1 
    // 2 - Player 2
    public board : Array<number> = [0,0,0,0,0,0,0,0,0];
    
    public player1: string = '';
    public player2: string = '';
    public gameStatus: GameStatus = GameStatus.turnPlayer1; 
    
    // Extra Information
    public gameNumber: number;
    public startedDate: Date = null; 
    public player1Name: string = '';
    public player2Name: string = '';    
    public endedDate: Date; 
    public lastTouchedDate: Date; 
    
    // Extra Information Related Methods
    public end() {
        if (this.startedDate==null) {
            this.startedDate = new Date();
        }
        this.endedDate = new Date();
    }
    
    public touch() {
        this.lastTouchedDate = new Date();
    }
    
    public isGameInactive() : boolean {
        if (!this.lastTouchedDate){
            this.touch();
        }
        return (new Date().getTime() - this.lastTouchedDate.getTime()) > TIMEOUT;
    }
    
    public constructor(gameId: string, gameNumber: number, player1: string) {
        this.gameId = gameId;
        this.player1 = player1;
        this.player2 = '';
        this.board = [0,0,0,0,0,0,0,0,0];
        this.gameStatus = GameStatus.turnPlayer1;
        this.gameNumber = gameNumber;
    }
    
    private isBoardComplete():boolean{
        let returnValue = true;
        this.board.forEach(element => {
            if (element == 0) {
                returnValue = false;
                return;
            }
        });
        return returnValue;
    }
    
    private hasRow(value: number): boolean{
        return  ((this.board[0]==value) && (this.board[1]==value) && (this.board[2]==value)) || 
        ((this.board[3]==value) && (this.board[4]==value) && (this.board[5]==value)) || 
        ((this.board[6]==value) && (this.board[7]==value) && (this.board[8]==value)) || 
        ((this.board[0]==value) && (this.board[3]==value) && (this.board[6]==value)) || 
        ((this.board[1]==value) && (this.board[4]==value) && (this.board[7]==value)) || 
        ((this.board[2]==value) && (this.board[5]==value) && (this.board[8]==value)) || 
        ((this.board[0]==value) && (this.board[4]==value) && (this.board[8]==value)) || 
        ((this.board[2]==value) && (this.board[4]==value) && (this.board[6]==value));
    }
    
    private checkGameEnded(): boolean{
        if (this.hasRow(1)) {
            this.gameStatus = GameStatus.endedWonPlayer1; 
            this.end();
            return true;
        }
        if (this.hasRow(2)) {
            this.gameStatus = GameStatus.endedWonPlayer2; 
            this.end();
            return true;
        }
        if (this.isBoardComplete()) {
            this.gameStatus = GameStatus.endedTie; 
            this.end();
            return true;
        }
        return false;
    }
    
    public isGameFull(): boolean {
        return (this.player1 !== '') && (this.player2 !== '');
    }
    
    public hasGameEnded(): boolean {
        return this.gameStatus >= GameStatus.endedTie;
    }
    
    public playerNumberOfUser(userId: string): number {
        if (this.player1 == userId) {
            return 1;
        }
        if (this.player2 == userId) {
            return 2;
        }
        return 0;  // userId is not a player
    }
    
    // Returns false if move was not played
    // Returns true if a move was correctly played
    public playMove(userId: string, position: number) : boolean {
        if (this.hasGameEnded()) {
            return false;
        }
        this.touch();
		if ((position<0) || (position>9)) {
            return false;
        }
        let playerNumber = this.playerNumberOfUser(userId);
		if ((playerNumber!=1) && (playerNumber!=2)) {
            return false;
        }
        
        if ((playerNumber == 1) && (this.gameStatus != GameStatus.turnPlayer1)) {
            return false;
        }
        if ((playerNumber == 2) && (this.gameStatus != GameStatus.turnPlayer2)) {
            return false;
        }
        
        if (this.board[position] != 0) {
            return false;
        }
        if (this.startedDate==null) {
            this.startedDate = new Date();
        }
        
        this.board[position] = playerNumber;        
        
        if (!this.checkGameEnded()) {
            if (playerNumber ==1) {
                this.gameStatus = GameStatus.turnPlayer2;
            } else {
                this.gameStatus = GameStatus.turnPlayer1;
            }                
        }
		return true;	
    }
    
    public cancelGame(userId: string) : boolean {
        if (this.hasGameEnded()) {
            return false;
        }
        let playerNumber = this.playerNumberOfUser(userId);
		if ((playerNumber!=1) && (playerNumber!=2)) {
            return false;
        }
        if (playerNumber == 1) {
            this.gameStatus = GameStatus.canceledByPlayer1;
            this.end();
            return true;
        }
        if (playerNumber == 2) {
            this.gameStatus = GameStatus.canceledByPlayer2;
            this.end();
            return true;
        }
    }
    
    public timeoutGame() : boolean {
        if (this.hasGameEnded()) {
            return false;
        }
        this.gameStatus = GameStatus.timeout;
        this.end();
        return true;
    }    
}