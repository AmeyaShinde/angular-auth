import { Injectable } from '@angular/core';
import { CanActivate, Router } from '@angular/router';
import { AuthService } from '../services/auth.service';
import { NgToastService } from 'ng-angular-popup';

@Injectable({
    providedIn: 'root'
})
export class AuthGuard implements CanActivate {
    
    constructor(
        private auth: AuthService,
        private router: Router,
        private toast: NgToastService
    ) { }

    canActivate(): boolean {
        if (this.auth.isLoggedIn()) {
            return true;
        } else {
            this.toast.error({ detail: 'Error', summary: "Please Login first!" });
            this.router.navigate(['login']);
            return false;
        }
    }
}
