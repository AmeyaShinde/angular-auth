import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormControl, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { NgToastService } from 'ng-angular-popup';
import ValidateForm from 'src/app/helper/validateForm';
import { AuthService } from 'src/app/services/auth.service';

@Component({
    selector: 'app-signup',
    templateUrl: './signup.component.html',
    styleUrls: ['./signup.component.scss']
})
export class SignupComponent implements OnInit {
    type: string = "password";
    isText: boolean = false;
    eyeIcon: string = "fa-eye-slash";
    signUpForm!: FormGroup;

    constructor(
        private fb: FormBuilder,
        private auth: AuthService,
        private router: Router,
        private toast: NgToastService
    ) { }

    ngOnInit(): void {
        this.signUpForm = this.fb.group({
            firstName: [ '', Validators.required ],
            lastName: [ '', Validators.required ],
            email: [ '', Validators.required ],
            userName: [ '', Validators.required ],
            password: [ '', Validators.required ]
        });
    }

    hideshowPass() {
        this.isText = !this.isText;
        this.isText ? this.eyeIcon = "fa-eye" : this.eyeIcon = "fa-eye-slash";
        this.isText ? this.type = "text" : this.type = "password";
    }

    onSignUp() {
        if (this.signUpForm.valid) {
            console.log(this.signUpForm.value);
            // Send the obj to database
            this.auth.signUp(this.signUpForm.value).subscribe({
                next: (res) => {
                    console.log(res);
                    this.toast.success({ detail: "SUCCESS", summary: res.message, duration: 5000 });
                    this.signUpForm.reset();
                    this.router.navigate(['login']);
                },
                error: (err) => {
                    this.toast.error({ detail: "ERROR", summary: err?.error.message, duration: 5000 });
                }
            });
        } else {
            // throw the error using toaster and with the required fields
            ValidateForm.validateAllFormFields(this.signUpForm);
            this.toast.error({ detail: "ERROR", summary: "Your form is invalid", duration: 5000 });
        }
    }

}
