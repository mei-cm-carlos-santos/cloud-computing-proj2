import { Injectable }      from '@angular/core';
import { Http, Response, Headers, RequestOptions }  from '@angular/http';
import { Router } from '@angular/router';
import { Observable }      from 'rxjs/Observable';
import { UserSecurityService }    from './security.service'
import { Global }    from './global.service'
import { RestBase } from './rest.base';

import 'rxjs/add/operator/catch';
import 'rxjs/add/operator/map';

@Injectable()
export class RestGameService extends RestBase {

  constructor (      
      protected http: Http, 
      protected router:Router, 
      protected userSecurity: UserSecurityService,
      protected global: Global) {
          super(http, router, userSecurity, global); 
          this.restUrl = 'http://localhost:7777/v1/';  // URL to web API
      }

  preregister(name: string, email: string, username: string): Observable<any[]> {
      let userInfo = { 
        'name': name,
        'email': email,
        'username': username,
      }       
      return this.http
            .post(this.restUrl+'preregister', userInfo)
            .map(this.extractData)
            .catch(this.handleError.bind(this));
  }

  topTen(): Observable<any[]> {
      return this.http
            .get(this.restUrl+'users/topten')
            .map(this.extractData)
            .catch(this.handleError.bind(this));
  }

  lobby(): Observable<any[]> {
      return this.http
            .get(this.restUrl+'games/lobby', this.authorizationOptions())
            .map(this.extractData)
            .catch(this.handleError.bind(this));
  }

  history(historyType: string): Observable<any[]> {
        return this.http
                .get(this.restUrl+'games/history/' + historyType, this.authorizationOptions())
                .map(this.extractData)
                .catch(this.handleError.bind(this));
  }

  createGame(): Observable<any[]> {
      return this.http
            .post(this.restUrl+'games', {}, this.authorizationOptions())
            .map(this.extractData)
            .catch(this.handleError.bind(this));
  }

  joinGame(gameId: string): Observable<any[]> {
      return this.http
            .post(this.restUrl+'games/join', {id:gameId}, this.authorizationOptions())
            .map(this.extractData)
            .catch(this.handleError.bind(this));
  }

  removeGame(gameId: string): Observable<any[]> {
      return this.http
            .post(this.restUrl+'games/remove', {id:gameId}, this.authorizationOptions())
            .map(this.extractData)
            .catch(this.handleError.bind(this));
  }
}