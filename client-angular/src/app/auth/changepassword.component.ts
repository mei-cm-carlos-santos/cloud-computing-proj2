import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';

import { RestAuthService } from '../services/rest.auth.service';
import { UserSecurityService } from '../services/security.service';

@Component({
    moduleId: module.id,
    selector: 'changepassword',
    templateUrl: 'changepassword.component.html'
})
export class ChangePasswordComponent implements OnInit {  
    complexForm : FormGroup;
    msgValidation: string;

    constructor (
        private fb: FormBuilder,
        private restAuthService: RestAuthService, 
        private userSecurity: UserSecurityService,
        private router:Router){} 

    ngOnInit(){
        this.complexForm = this.fb.group({
                'oldpassword' : [null, Validators.required],
                'newpassword1' : [null, Validators.required],
                'newpassword2' : [null, Validators.required]
            }, {validator: this.matchingPasswords('newpassword1', 'newpassword2')});
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
        this.msgValidation = "";
        this.complexForm.reset();
    }    

    submitForm(form: any, event: Event): void{
        for (let i in this.complexForm.controls) {
            this.complexForm.controls[i].markAsDirty();
        }
        if (this.complexForm.invalid) {
            event.preventDefault();
        } else {
            this.changePassword(form);
        }
    }   
    

    changePassword(form: any){
        this.restAuthService.changePassword(form.oldpassword, form.newpassword1)
            .subscribe(
                updatedUser  => {
                    this.router.navigateByUrl('/home');                      
                    },
                error => {
                    this.msgValidation = "Password was not changed! Probably, old password is incorrect.";
            }); 
    }
}