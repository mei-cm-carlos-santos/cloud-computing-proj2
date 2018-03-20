const bcrypt = require('bcrypt');
//const jwt = require('jsonwebtoken');
const jwtDecode = require('jwt-decode');
             
import {MongoDB} from '../db/mongodb';
import {AppConfig} from '../app/app.config';

export class UserInfo {
    userID: String;
    username: String;
    name: String;
    email: String;

    constructor (userDB: any){
        this.username = userDB.username;
        this.name = userDB.name;
        this.email = userDB.email;
    } 
}

export class AuthUtil {
    public static validatePassword(password, passwordHash){
        return AuthUtil.checkHash(password, passwordHash); 
    }

    // Original - MEAN ONLY:
    /*
    public static createNewToken(userInfo: UserInfo): string { 
        // UserInfo is the Token Payload
        var token = jwt.sign(
            userInfo, 
            AppConfig.secret,
            {
                issuer: AppConfig.hostname,
                expiresIn: AppConfig.tokenExpirationTime + 'm'
            });
        return token;    
    }
    */

    public static validateToken(token: string): UserInfo { 
        // UserInfo is the Token Payload
        try {
            // Original - MEAN ONLY:
            //let decoded = jwt.verify(token, AppConfig.secret);
            //return decoded as UserInfo;

            let dataFromToken = jwtDecode(token).data;
            let userInfo =new UserInfo(dataFromToken);
            userInfo.userID = dataFromToken.userID; 
            return userInfo;
            
        } catch(err) {
            return null;
        }        
    }

    public static  generateHash(value: string) {
        let salt = bcrypt.genSaltSync(10);
        return bcrypt.hashSync(value, salt);
    }

    public static checkHash(value: string, hash: string) {
        return bcrypt.compareSync(value, hash); 
    }
    

}