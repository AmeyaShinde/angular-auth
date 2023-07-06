import { Injectable } from '@angular/core';
import {
    HttpRequest,
    HttpHandler,
    HttpEvent,
    HttpInterceptor,
    HttpErrorResponse
} from '@angular/common/http';
import { Observable, catchError, switchMap, throwError } from 'rxjs';
import { AuthService } from '../services/auth.service';
import { NgToastService } from 'ng-angular-popup';
import { Router } from '@angular/router';
import { TokenApiDto } from '../models/tokenApiDto';

@Injectable()
export class TokenInterceptor implements HttpInterceptor {

    constructor(private auth: AuthService, private toast: NgToastService, private router: Router) {}

    intercept(request: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
        const myToken = this.auth.getToken();

        if (myToken) {
            request = request.clone({
                setHeaders: { Authorization: `Bearer ${ myToken }` }
            });
            return next.handle(request).pipe(
                catchError((err: any) => {
                    if (err instanceof HttpErrorResponse) {
                        if (err.status === 401) {
                            // this.toast.warning({ detail: 'Warning', summary: 'Token is expired, Login again' });
                            // this.router.navigate(['login']);
                            // handle
                            return this.handleUnAuthorizedError(request, next);
                        }
                    }
                    return throwError(() => new Error("Some other error occured"));
                })
            );
        }
        return next.handle(request);
    }

    handleUnAuthorizedError(req: HttpRequest<any>, next: HttpHandler) {
        let tokenApiDto = new TokenApiDto();
        tokenApiDto.accessToken = this.auth.getToken()!;
        tokenApiDto.refreshToken = this.auth.getRefreshToken()!;
        return this.auth.renewToken(tokenApiDto).pipe(
            switchMap((data: TokenApiDto) => {
                this.auth.storeRefreshToken(data.refreshToken);
                this.auth.storeToken(data.accessToken);
                req = req.clone({
                    setHeaders: { Authorization: `Bearer ${ data.accessToken }` } // "Bearer " + myToken
                });
                return next.handle(req);
            }),
            catchError((err) => {
                return throwError(() => {
                    this.toast.warning({ detail: 'Warning', summary: 'Token is expired, Login again' });
                    this.router.navigate(['login']);
                });
            })
        )
    }
}
