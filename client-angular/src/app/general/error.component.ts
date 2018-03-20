import { Component, OnInit } from '@angular/core';
import {Global}    from '../services/global.service'

@Component({
    moduleId: module.id,
    selector: 'error',
    templateUrl: 'error.component.html'
})

export class ErrorComponent implements OnInit {
    public errorTitle: string = "";
    public errorMessage: string = "";
    public errorSecundaryMessage: string = "";    

  constructor (
      private global: Global) {}

    ngOnInit(){
        if (this.global.flashError != null) {
            this.errorTitle= this.global.flashError.errorTitle;
            this.errorMessage= this.global.flashError.errorMessage;
            this.errorSecundaryMessage= this.global.flashError.errorSecundaryMessage;
            this.global.resetAll();
        }
    }
}