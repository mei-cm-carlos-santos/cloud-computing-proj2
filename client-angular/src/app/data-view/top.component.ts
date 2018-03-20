import { Component, OnInit } from '@angular/core';
import {RestGameService} from '../services/rest.game.service'

@Component({
    moduleId: module.id,
    selector: 'top',
    templateUrl: 'top.component.html'
})

export class TopComponent implements OnInit{
    public users: Array<any> = [];
    public errorMessage: string;

    constructor (
        private restGameService: RestGameService){} 

    ngOnInit(){
        this.fillUsers();
    }

    fillUsers() {
        this.restGameService.topTen()
                .subscribe(
                     users  => this.users = users,
                     error =>  this.errorMessage = error);
    }

    errorMessageExists() {
        return this.errorMessage != "";
    }
}