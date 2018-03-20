import {RestBase} from './rest.base';
import {HandlerSettings} from '../app/handler.settings';
import {AuthUtil} from '../security/auth.util'
//import {MongoDB} from '../db/mongoDB';

export class RestUsers extends RestBase{
    constructor(handlerSettings: HandlerSettings){
        super(handlerSettings);
    }

    public topten = (request: any, response: any, next: any) => {
        this.mongoDB.User
            .find()
            .sort({totalVictories:-1})
            .limit(10)
            .select('username name totalVictories')
            .then(users => {
                response.json(users || []);
                next();
            }).catch(function(err){
                console.error(err);
            });
    }

    public updateMyUser = (request: any, response: any, next: any) => {
        if ((request.params.name == null) || (request.params.email == null)){
            console.error('RestUsers.updateUser: Invalid parameters');
            response.send(400, {'msg': 'Invalid parameters'} || {});
            return next();
        }        
        let name = request.params.name;
        let email = request.params.email;
        let userID = request.user.userID;

        this.handlerSettings.mongoDB.User
            .findById(userID)
            .then(user => {
                if (user === null) {
                    response.send(401, 'Unauthorized');
                    next();
                } 
                else {
                    user.name = name;
                    user.email = email;
                    user.save().then(function (updatedUser) {
                        updatedUser.passwordHash = "";
                        response.json({'msg': 'User has changed', 'updatedUser': updatedUser} || {});
                        next();
                    }).catch(function(err){
                        console.error(err);
                        next();
                    });
                }
            }).catch(function(err){
                console.error(err);
                response.send(401, 'Unauthorized');
                next();
            });
    }    
            

/*
    public deleteUser = (request: any, response: any, next: any) => {
        if (request.params.id == null){
            console.error('RestAuth.deleteUser: No Object ID parameter');
            response.send(400, {'msg': 'No Object ID parameter'} || {});
            return next();
        }
        let ObjectId = require('mongoose').Types.ObjectId;
        if (!ObjectId.isValid(request.params.id)) {
            console.error('RestAuth.deleteUser: Object ID ' + request.params.id + ' is invalid');
            response.send(400, {'msg': 'Object ID ' + request.params.id + ' is invalid'} || {});
            return next();
        }
        let id = new ObjectId(request.params.id);
        
        this.mongoDB.User.findByIdAndRemove(id).then(function(deletedUser) {
            response.send(200, {'msg': 'User was deleted', 'deletedUser': deletedUser} || {});
            next();
        }).catch(function(err){
            console.error('RestAuth.deleteUser: Error deleting user with Object ID ' + request.params.id + '. Error Message = ' + err);
            response.send(400, {'msg': 'Error deleting user with Object ID ' + request.params.id, 'msgError': err} || {});
            return next();
        });
    }    
*/
/*
    public destroyAllUsers = (request: any, response: any, next: any) => {        
        this.mongoDB.User.remove().then(function(removed) {
            response.send(200, {'msg': 'All users have been deleted', 'totalUsersDelete': removed} || {});
            next();
        }).catch(function(err){
            console.error('RestAuth.destroyAllUsers: Error deleting all users. Error Message = ' + err);
            response.send(400, {'msg': 'Error deleting all users', 'msgError': err} || {});
            return next();
        });
    }        
*/    
}
