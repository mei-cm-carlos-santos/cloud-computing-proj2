import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Global }    from '../services/global.service'

import {RestAuthService} from '../services/rest.auth.service';
import {UserSecurityService} from '../services/security.service';

@Component({
    moduleId: module.id,
    selector: 'login',
    templateUrl: 'login.component.html'
})
export class LoginComponent implements OnInit { 
    complexForm : FormGroup;
    msgTitle: string;
    msgWarning: string;
    msgValidation: string;
    redirectTo: string;

    constructor (
        private fb: FormBuilder,
        private restAuthService: RestAuthService, 
        private router:Router,
        private userSecurity: UserSecurityService,
        private global: Global){} 

    ngOnInit(){
        this.complexForm = this.fb.group({
                'username': [null, Validators.compose([Validators.required, Validators.minLength(2), Validators.maxLength(20)])],
                'password' : [null, Validators.required]
            });
        this.resetData();

        this.msgTitle = "";
        this.msgWarning = "";
        this.redirectTo = "/lobby";

        if (this.global.flashMsg != null) {
            this.msgTitle= this.global.flashMsg.msgTitle;
            this.msgWarning= this.global.flashMsg.msgWarning;
        }
        if (this.global.redirectTo != "") {
            this.redirectTo= this.global.redirectTo;
        }
        this.global.resetAll();
    }

    private resetData(){
        this.msgValidation = "";
        this.complexForm.reset();
    }    

    showWarning(){
        return this.msgTitle != "";
    }

    submitForm(form: any, event: Event): void{
        for (let i in this.complexForm.controls) {
            this.complexForm.controls[i].markAsDirty();
        }
        if (this.complexForm.invalid) {
            event.preventDefault();
        } else {
            this.login(form);
        }
    }   

    private login(form: any){
        this.restAuthService.authenticate(form.username, form.password)
                .subscribe(
                    token  => {
                        this.userSecurity.authenticateUserFromToken(token);
                        this.router.navigateByUrl(this.redirectTo);                        
                        },
                    error => {
                        this.msgValidation = "Credentials are invalid!";
                }); 
    }
    
}