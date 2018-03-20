import {Injectable} from '@angular/core';

@Injectable()
export class Global {
    public flashError: any;
    public flashMsg: any;
    public redirectTo: string;

    constructor () {
        this.resetAll();
    }    

    resetAll() {
        this.flashError = null;
        this.flashMsg = null;
        this.redirectTo = "";
    }

}