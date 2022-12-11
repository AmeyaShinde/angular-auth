import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormControl, FormGroup, Validators } from '@angular/forms';
import ValidateForm from 'src/app/helper/validateForm';

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

    constructor(private fb: FormBuilder) { }

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

    onSubmit() {
        if (this.loginForm.valid) {
            console.log(this.loginForm.value);
            // Send the obj to database
        } else {
            console.log("Form is not valid.");
            // throw the error using toaster and with the required fields
            ValidateForm.validateAllFormFields(this.loginForm);
            alert("Your form is invalid.");
        }
    }

}
