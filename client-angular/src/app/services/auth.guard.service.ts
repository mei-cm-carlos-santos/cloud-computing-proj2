import { Injectable }     from '@angular/core';
import { CanActivate }    from '@angular/router';
import {UserSecurityService} from './security.service';

@Injectable()
export class AuthGuard implements CanActivate {
    constructor (
        private userSecurity: UserSecurityService){} 

    canActivate() {
        return this.userSecurity.isLogged();
    }
}
