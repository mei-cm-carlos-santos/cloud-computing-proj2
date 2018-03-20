import { Http, Response, Headers, RequestOptions }  from '@angular/http';
import { Router } from '@angular/router';
import { Observable }      from 'rxjs/Observable';
import { UserSecurityService }    from './security.service'
import { Global }    from './global.service'

import 'rxjs/add/operator/catch';
import 'rxjs/add/operator/map';

export class RestBase {
  constructor (
      protected http: Http, 
      protected router:Router, 
      protected userSecurity: UserSecurityService,
      protected global: Global) {}

  protected restUrl = '';

  protected authorizationOptions() {
      let headers = new Headers({'Content-Type': 'application/json'});  
      if (this.userSecurity.isLogged())
         headers.append('Authorization','Bearer ' + this.userSecurity.token);
      return new RequestOptions({headers: headers});
  }
  

  protected extractData(res: Response) {
    let body = res.json();
    return body || { };
  }

  protected handleError (error: Response | any, expectedStatus: number[] = []) {
    // In a real world app, we might use a remote logging infrastructure
    
    let errMsg: string;
    let flash = {};
    let loginMsg = {}; 
    if (error instanceof Response) {
        let body:any;
        try {
            body = error.json() || '';
        }
        catch (e){
            body = error;
        }
        const err = body.error || JSON.stringify(body);
        errMsg = `${error.status} - ${error.statusText || ''} ${err}`;        
        if (expectedStatus.indexOf(error.status) >= 0) {
            return Observable.throw(errMsg);
        }
        if (error.status == 401) {
            flash = {
                errorTitle: 'Unauthorized Access',
                errorMessage: 'You do not have permission to access the resource "' + error.url + '"',
                errorSecundaryMessage: errMsg
            };
            loginMsg = {
                msgTitle: 'Unauthorized Access',
                msgWarning: 'Please enter your credentials to access requested resource' 
            }

        } else {
            flash = {
                errorTitle: 'REST API Access Error',
                errorMessage: 'An error has occurred when accessing REST API',
                errorSecundaryMessage: errMsg
            }
        }
    } else {
        if (expectedStatus.indexOf(error.status) >= 0) {
            return Observable.throw(errMsg);
        }
        errMsg = error.message ? error.message : error.toString();
        flash = {
            errorTitle: 'REST API Access Error',
            errorMessage: 'An error has occurred when accessing REST API',
            errorSecundaryMessage: errMsg
        }
    }
    if (error.status == 401) {
        this.global.redirectTo = window.location.pathname;
        this.global.flashMsg = loginMsg;
        this.router.navigate(['/login']);
    }
    else {
        this.global.flashError = flash;
        this.router.navigate(['/error']);
    }
    return Observable.throw(errMsg);
  }


}