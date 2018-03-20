import { Injectable } from '@angular/core';
import { Http, Response } from '@angular/http';
import {UserSecurityService}    from './security.service'

import {Observable} from 'rxjs/Observable';

import * as io from 'socket.io-client';

class SocketError extends Error {
    constructor(m: string) {
        super(m);
    }
}

@Injectable()
export class WebSocketService {
    private socket: SocketIOClient.Socket;

    constructor(private userSecurity: UserSecurityService) {
        if (!this.socket) {
            this.socket = io('http://localhost:7777');  // URL to webSockets                     
        }
    }

    identifyMyself() {
        if (this.userSecurity.isLogged()){
            this.socket.emit('identifyMyself', {'token': this.userSecurity.token});
        }            
        else {
            throw new SocketError('User is not logged - it cannot be identified');
        }
    }

    myActiveGames() {
        this.socket.emit('myActiveGames', {'notrelevant':'nothing relevant'});
    }

    enterGame(gameId: string) {
        this.socket.emit('enterGame', {'gameId': gameId});
    }

    quitGame(gameId: string) {
        this.socket.emit('quitGame', {'gameId': gameId});
    }

    leaveGame(gameId: string) {
        this.socket.emit('leaveGame', {'gameId': gameId});
    }

    leaveAllGames() {
        this.socket.emit('leaveAllGames', {'notrelevant':'nothing relevant'});
    }

    playGame(gameId: string, position: number) {
        this.socket.emit('play', {'gameId': gameId, 'position': position});
    }

    // Messages from the server
    getMyListOfGames(): Observable<any> {
        return this.listenOnChannel('myListOfGames');
    }

    getRefreshGame(): Observable<any> {
        return this.listenOnChannel('refreshGame');
    }

    getGameEnded(): Observable<any> {
        return this.listenOnChannel('gameEnded');
    }

    getGameInvalidPlay(): Observable<any> {
        return this.listenOnChannel('gameInvalidPlay');
    }

    getLobbyChanged(): Observable<any> {
        return this.listenOnChannel('lobbyChanged');
    }

    getGamesListChanged(): Observable<any> {
        return this.listenOnChannel('gamesPlayingChanged');
    }

    getLobbyJoinGame(): Observable<any> {
        return this.listenOnChannel('lobby_joinGame');
    }

    private listenOnChannel(channel: string): Observable<any> {
        return new Observable((observer:any) => {            
            this.socket.on(channel, (data:any) => {
                observer.next(data);
            });
            return () => {
                this.socket.removeEventListener(channel);
                //this.socket.disconnect();

                // NOTA: MUITO IMPORTANTE
                // Se usar o sicket disconnect, quando se faz unsubscribe, o socket é fechada!!!!
                // Em vez disso remove-se apenas os listeners para esse socket, mantendo o socket aberto
            }
        });
    }
}
