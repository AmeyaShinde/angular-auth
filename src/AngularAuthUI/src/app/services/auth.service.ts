import { HttpClient } from "@angular/common/http";
import { Injectable } from '@angular/core';
import { Router } from "@angular/router";

@Injectable({
    providedIn: 'root'
})
export class AuthService {

    private baseUrl: string = "https://localhost:7276/api/User";

    constructor(private http: HttpClient, private router: Router) { }

    signUp(userObj: any) {
        return this.http.post<any>(`${ this.baseUrl }/register`, userObj);
    }

    login(loginObj: any) {
        return this.http.post<any>(`${ this.baseUrl }/authenticate`, loginObj);
    }

    logout() {
        localStorage.clear();
        this.router.navigate(['login']);
    }

    storeToken(tokenValue: string) {
        localStorage.setItem('token', tokenValue);
    }

    getToken() {
        return localStorage.getItem('token');
    }

    isLoggedIn(): boolean {
        return !!this.getToken();
    }
}
