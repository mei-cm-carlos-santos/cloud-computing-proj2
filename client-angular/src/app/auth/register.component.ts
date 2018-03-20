import { Component , OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';

import {RestAuthService} from '../services/rest.auth.service';
import {RestGameService} from '../services/rest.game.service';
import {UserSecurityService} from '../services/security.service';

@Component({
    moduleId: module.id,
    selector: 'register',
    templateUrl: 'register.component.html'
})
export class RegisterComponent implements OnInit  {  
    complexForm : FormGroup;
    lastRepeatedUsername: string;
    lastRepeatedEmail: string;


    constructor (
        private fb: FormBuilder,
        private restAuthService: RestAuthService, 
        private restGameService: RestGameService, 
        private userSecurity: UserSecurityService,
        private router:Router){} 

    ngOnInit(){ 
        this.complexForm = this.fb.group({
//                'name' : [null,  Validators.compose([Validators.required, Validators.minLength(2), Validators.maxLength(50)])],
                'name' : [null,  [Validators.required, Validators.minLength(2), Validators.maxLength(50)]],
                'username': [null, Validators.compose([Validators.required, Validators.minLength(2), Validators.maxLength(20)])],
                'email' : [null, Validators.compose([Validators.required, Validators.pattern(/^[a-z0-9!#$%&'*+\/=?^_`{|}~.-]+@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i)])],
                'password' : [null, Validators.required],
                'password2' : [null, Validators.required]
            }, {validator: this.matchingPasswords('password', 'password2')});
        this.resetData();
    }

    private matchingPasswords = (passwordKey: string, confirmPasswordKey: string) => {
        return (group: FormGroup): {[key: string]: any} => {
            let password = group.controls[passwordKey];
            let confirmPassword = group.controls[confirmPasswordKey];
            if (password.value !== confirmPassword.value) {
                return {
                    mismatchedPasswords: true
                };
            }
        }
    }

    private resetData(){
        this.lastRepeatedUsername="";
        this.lastRepeatedEmail="";
        this.complexForm.reset();
    }

    submitForm(form: any, event: Event): void{
        for (let i in this.complexForm.controls) {
            this.complexForm.controls[i].markAsDirty();
        }
        if (this.complexForm.invalid) {
            event.preventDefault();
        } else {
            this.register(form);
        }
    }    

    private register(form: any){
        let component: RegisterComponent = this;
        this.restAuthService.checkUniqueUsername(form.username)
                .subscribe(
                    username  => {
                        component.lastRepeatedUsername = '';
                        component.restAuthService.checkUniqueEmail(form.email)
                                .subscribe(
                                    email  => {
                                        component.lastRepeatedEmail = "";
                                        component.restGameService.preregister(form.name, form.email, form.username)
                                                .subscribe(
                                                    userInfo => {
                                                        component.restAuthService.registerUser(userInfo, form.password)
                                                                .subscribe(
                                                                    token  => {
                                                                        this.userSecurity.authenticateUserFromToken(token);
                                                                        this.router.navigateByUrl('/home');                      
                                                                        },
                                                                    error => {
                                                                        console.error(error); //registerUser
                                                                }); 
                                                    },
                                                    error => { // preregister
                                                        console.error(error);
                                                });
                                        },
                                    error => { // checkUniqueEmail
                                        component.lastRepeatedEmail = form.email;
                                }); 
                        },
                    error => { // checkUniqueUsername
                        component.lastRepeatedUsername = form.username;
                }); 
    }
}