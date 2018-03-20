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
export class RestAuthService extends RestBase {

  constructor (      
      protected http: Http, 
      protected router:Router, 
      protected userSecurity: UserSecurityService,
      protected global: Global) {
          super(http, router, userSecurity, global); 
          this.restUrl = 'http://cnprj2.test/api/';  // URL to web API
      }

  checkUniqueUsername(username: string): Observable<any[]> {
      return this.http
            .post(this.restUrl+'uniqueusername.php',JSON.stringify({'username':username}))
            .map(this.extractData)
            .catch(this.handleError.bind(this, [403]));
  }

  checkUniqueEmail(email: string): Observable<any[]> {
      return this.http
            .post(this.restUrl+'uniqueemail.php',JSON.stringify({'email':email}))
            .map(this.extractData)
            .catch(this.handleError.bind(this, [403]));
  }

  authenticate(username: string, password: string): Observable<any[]> {
      let credentials = {
        'username': username,
        'password':password
      } 
      return this.http
            .post(this.restUrl+'authenticate.php', JSON.stringify(credentials))
            .map(this.extractData)
            .catch(this.handleError.bind(this, [401]));
  }  

  registerUser(userInfoFromPreRegister: any, password: string): Observable<any[]> {
      let userInfo = { 
        'name': userInfoFromPreRegister.name,
        'email': userInfoFromPreRegister.email,
        'username': userInfoFromPreRegister.username,
        'password': password,
        'id': userInfoFromPreRegister.userID
      } 
      return this.http
            .post(this.restUrl+'register.php', JSON.stringify(userInfo))
            .map(this.extractData)
            .catch(this.handleError.bind(this));
  }  

  changePassword(oldpassword: string, newpassword: string){
      let passInfo = { 
        'oldpassword': oldpassword,
        'newpassword': newpassword,
      }
      return this.http
            .put(this.restUrl+'changepassword.php', JSON.stringify(passInfo), this.authorizationOptions())
            .map(this.extractData)
            .catch(this.handleError.bind(this, [401]));
  }
}