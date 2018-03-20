import {RestBase} from './rest.base'
import {HandlerSettings} from '../app/handler.settings';
import {AuthUtil, UserInfo} from '../security/auth.util';

export class RestAuth extends RestBase{
    constructor(handlerSettings: HandlerSettings){
        super(handlerSettings);
    }

    public preRegisterUser = (request: any, response: any, next: any) => {
        if ((request.params.name == null) || (request.params.email == null) ||
            (request.params.username == null)){
            response.send(400, {'msg': 'Invalid parameters'} || {});
            return next();
        }        
        let name = request.params.name;
        let email = request.params.email;
        let username = request.params.username;

        let newUser = new this.mongoDB.User();
        newUser.username = username;
        newUser.name= name;
        newUser.email= email;
        newUser.totalGames= 0;
        newUser.totalVictories= 0;
        newUser.save().then(function (createdUser) {
            let userInfo = new UserInfo(createdUser);
            userInfo.userID = createdUser._id;
            //let token = AuthUtil.createNewToken(userInfo);
            //response.send(200, token || {});                       
            response.send(200, userInfo || {});                        
            next();
        }).catch(function(err){
            console.error(err);
            next();
        });
    }

/*
 Follwing methods are only used on MEAN full stack solution:
*/ 

/*
    public authenticate = (request: any, response: any, next: any) => {
        if ((request.params.username == null) || (request.params.password == null)){
            response.send(400, {'msg': 'Invalid parameters'} || {});
            return next();
        }        
        let username  = request.params.username;
        let password  = request.params.password;
        this.handlerSettings.mongoDB.User
            .findOne({'username':username})
            .select('userid username passwordHash name email')
            .then(user => {
                if (user === null) {
                    response.send(401, 'Unauthorized');
                    next();
                } 
                else {
                    if (AuthUtil.validatePassword(password, user.passwordHash)) {
                        let userInfo = new UserInfo(user);
                        userInfo.userID = user._id;
                        let token = AuthUtil.createNewToken(userInfo);
                        response.send(200, token || {});                        
                        next();
                    }
                    else {
                        response.send(401, 'Unauthorized');
                        next();
                    }
                }
            }).catch(function(err){
                console.error(err);
                response.send(401, 'Unauthorized');
                next();
            });
    }

    public registerUser = (request: any, response: any, next: any) => {
        if ((request.params.name == null) || (request.params.email == null) ||
            (request.params.username == null) || (request.params.password == null)){
            response.send(400, {'msg': 'Invalid parameters'} || {});
            return next();
        }        
        let name = request.params.name;
        let email = request.params.email;
        let username = request.params.username;
        let password = request.params.password;

        let newUser = new this.mongoDB.User();
        newUser.username = username;
        newUser.passwordHash= AuthUtil.generateHash(password);
        newUser.name= name;
        newUser.email= email;
        newUser.totalGames= 0;
        newUser.totalVictories= 0;
        newUser.save().then(function (createdUser) {
            let userInfo = new UserInfo(createdUser);
            userInfo.userID = createdUser._id;
            let token = AuthUtil.createNewToken(userInfo);
            response.send(200, token || {});                        
            next();
        }).catch(function(err){
            console.error(err);
            next();
        });
    }

    public checkUniqueUsername = (request: any, response: any, next: any) => {
        if (request.params.username == null){
            console.error('RestAuth.checkUniqueUsername: Invalid parameters');
            response.send(400, {'msg': 'Invalid parameters'} || {});
            return next();
        }  
        let username = request.params.username;
        this.handlerSettings.mongoDB.User
            .findOne({'username':username})
            .select('username')
            .then(user => {                
                if (user === null) {
                    response.send(200, {'msg': 'Username does not exist on database'} || {});
                    next();
                }   
                else {
                    response.send(403, {'msg': 'Username already exists'} || {});
                    next();
                }
            }).catch(function(err){
                console.error(err);
                response.send(401, 'Something went wrong');
                next();
            });
    }

    public checkUniqueEmail = (request: any, response: any, next: any) => {
            if (request.params.email == null){
                console.error('RestAuth.checkUniqueEmail: Invalid parameters');
                response.send(400, {'msg': 'Invalid parameters'} || {});
                return next();
            }  
            let email = request.params.email;
            this.handlerSettings.mongoDB.User
                .findOne({'email':email})
                .select('email')
                .then(user => {
                    if (user === null) {
                        response.send(200, {'msg': 'Email does not exist on database'} || {});
                        next();
                    } 
                    else {
                        response.send(403, {'msg': 'Email already exists'} || {});
                        next();
                    }
                }).catch(function(err){
                    console.error(err);
                    response.send(401, 'Something went wrong');
                    next();
                });
        }    

    public changePassword = (request: any, response: any, next: any) => {
        if ((request.params.oldpassword == null) || (request.params.newpassword == null)){
            console.error('RestAuth.changePassword: Invalid parameters');
            response.send(400, {'msg': 'Invalid parameters'} || {});
            return next();
        }  

        let userID = request.user.userID;
        
        let oldPassword = request.params.oldpassword;
        let newPassword = request.params.newpassword;

        this.handlerSettings.mongoDB.User
            .findById(userID)
            .then(user => {
                if (user === null) {
                    response.send(401, 'Unauthorized');
                    next();
                } 
                else {
                    if (AuthUtil.validatePassword(oldPassword, user.passwordHash)) {
                        user.passwordHash= AuthUtil.generateHash(newPassword);                        
                        user.save().then(function (updatedUser) {
                            updatedUser.passwordHash = "";
                            response.json({'msg': 'User password has changed', 'updatedUser': updatedUser} || {});
                            next();
                        }).catch(function(err){
                            console.error(err);
                            next();
                        });
                    }
                    else {
                        console.error('Unauthorized');   
                        response.send(401, 'Unauthorized');
                        next();
                    }
                }
            }).catch(function(err){
                console.error(err);
                response.send(401, 'Unauthorized');
                next();
            });
    }
*/        
}
