import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormControl, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { NgToastService } from 'ng-angular-popup';
import ValidateForm from 'src/app/helper/validateForm';
import { AuthService } from 'src/app/services/auth.service';
import { UserStoreService } from 'src/app/services/user-store.service';

@Component({
    selector: 'app-login',
    templateUrl: './login.component.html',
    styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {

    type: string = "password";
    isText: boolean = false;
    eyeIcon: string = "fa-eye-slash"
    loginForm!: FormGroup;

    constructor(
        private fb: FormBuilder,
        private auth: AuthService,
        private router: Router,
        private toast: NgToastService,
        private userStore: UserStoreService
    ) { }

    ngOnInit(): void {
        this.loginForm = this.fb.group({
            username: [ '', Validators.required ],
            password: [ '', Validators.required ]
        });
    }

    hideshowPass() {
        this.isText = !this.isText;
        this.isText ? this.eyeIcon = "fa-eye" : this.eyeIcon = "fa-eye-slash";
        this.isText ? this.type = "text" : this.type = "password";
    }

    onLogin() {
        if (this.loginForm.valid) {
            // Send the obj to database
            this.auth.login(this.loginForm.value).subscribe({
                next: (res) => {
                    console.log(res);
                    this.toast.success({ detail: "SUCCESS", summary: res.message, duration: 5000 });
                    this.loginForm.reset();
                    this.auth.storeToken(res.tokenApiDto.accessToken);
                    this.auth.storeRefreshToken(res.tokenApiDto.refreshToken);
                    const tokenPayload = this.auth.decodedToken();
                    this.userStore.setFullNameForStore(tokenPayload.unique_name);
                    this.userStore.setRoleForStore(tokenPayload.role);
                    this.router.navigate(['dashboard']);
                },
                error: (err) => {
                    this.toast.error({ detail: "ERROR", summary: err?.error.message, duration: 5000 });
                }
            });
        } else {
            // throw the error using toaster and with the required fields
            ValidateForm.validateAllFormFields(this.loginForm);
            this.toast.error({ detail: "ERROR", summary: "Your form is invalid", duration: 5000 });
        }
    }

}
