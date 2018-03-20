//const jwtDecode = require('jwt-decode');
import * as jwtDecode from 'jwt-decode';

import { Injectable }      from '@angular/core';

import {Global}    from './global.service'

export class UserInfo {
    userID: String;
    username: String;
    name: String;
    email: String;

    constructor (userDB: any){
        if (userDB != undefined) {
            this.userID = userDB.userID;
            this.username = userDB.username;
            this.name = userDB.name;
            this.email = userDB.email;
        }
    }
}

@Injectable()
export class UserSecurityService {
    public userInfo: UserInfo = null;
    public token: string = "";
  
    constructor (private global: Global) {
        this.reliveTokenFromStorage();
    }

    private reliveTokenFromStorage() {
        let token = localStorage.getItem('token');
        if (token != null) {
            this.token = token;
            // Original - MEAN ONLY:
            //this.userInfo = new UserInfo(jwtDecode(this.token));
            this.userInfo = new UserInfo(jwtDecode(this.token).data);
            this.global.resetAll();
        }            
    }

    public authenticateUserFromToken(token: any) {
        this.token = token;
        // Original - MEAN ONLY:
        //this.userInfo = new UserInfo(jwtDecode(this.token));
        this.userInfo = new UserInfo(jwtDecode(this.token).data);
        localStorage.setItem('token', this.token),
        this.global.resetAll();
    }

    public logoutUser(){
        this.userInfo = null;
        this.token = "";
        localStorage.removeItem('token'),
        this.global.resetAll();
    }

    public isLogged(){
        return this.userInfo != null;
    }

    public getUserName(){
        if (this.userInfo == null){
            return "";
        }
        return this.userInfo.username;
    }
    public getName(){
        if (this.userInfo == null){
            return "";
        }
        return this.userInfo.name;
    }
    public getEMail(){
        if (this.userInfo == null){
            return "";
        }
        return this.userInfo.email;
    }
    public getUserID(){
        if (this.userInfo == null){
            return "";
        }
        return this.userInfo.userID;
    }    
}