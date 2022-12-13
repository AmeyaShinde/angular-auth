import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormControl, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import ValidateForm from 'src/app/helper/validateForm';
import { AuthService } from 'src/app/services/auth.service';

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

    constructor(private fb: FormBuilder, private auth: AuthService, private router: Router) { }

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
            console.log(this.loginForm.value);
            // Send the obj to database
            this.auth.login(this.loginForm.value).subscribe({
                next: (res) => {
                    alert(res.message);
                    this.loginForm.reset();
                    this.router.navigate(['dashboard']);
                },
                error: (err) => {
                    alert(err?.error.message);
                }
            });
        } else {
            console.log("Form is not valid.");
            // throw the error using toaster and with the required fields
            ValidateForm.validateAllFormFields(this.loginForm);
            alert("Your form is invalid.");
        }
    }

}
