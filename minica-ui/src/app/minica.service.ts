import { Injectable } from '@angular/core';
import { Observable, of } from 'rxjs';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { catchError, map, tap, finalize } from 'rxjs/operators';
import {MatSnackBar} from '@angular/material/snack-bar';

export function reportError<T>(theBar:MatSnackBar, message: string, action:string):Observable<T> {
    console.log("error => " + message);
    theBar.open(message, action, {duration: 3000, panelClass: "error-snack-bar"});
    return of({} as T);
  }

export function withLoading<T>(functionObject:TrapFunc<T>, errorer?:ErrorFunc<T>):Observable<T> {
    return trap(functionObject, showLoading, hideLoading , errorer)
}

export function trap<T>(functionObject: TrapFunc<T>, starter?:()=>void, ender?:()=>void, errorer?:ErrorFunc<T>):Observable<T> {
    if(starter) {
       starter();
    }
    if(errorer) {
      console.log("With errorer " + errorer);
      return functionObject().pipe(
        tap(result => console.log(`Trap Begin...`)),
        catchError(errorer),
        finalize(() => {
          console.log(`Trap End..`);
          if(ender) {
            ender();
          }
        })
      );
    } else {
      return functionObject().pipe(
        tap(result => console.log(`Trap Begin...`)),
        finalize(() => {
          console.log(`Trap End..`);
          if(ender) {
            ender();
          }
        })
      );
    }
  }
export function showLoading() {
    console.log("Showing loading...")
    document.getElementById("loading-layer")!.style!.display = "block";
  }
export function hideLoading() {
    console.log("Hiding loading...")
    document.getElementById("loading-layer")!.style!.display = "none";
}

export function reportSuccess(theBar:MatSnackBar, message:string, action: string) {
    console.log("success => " + message);
    theBar.open(message, action, {duration: 3000, panelClass: "success-snack-bar"});
  }
export interface CreateCADialogData {
  commonName: string;
  countryCode: string;
  state: string;
  city: string;
  organization: string;
  organizationUnit: string
  validDays: string;
  digestAlgorithm: string;
  keyLength: string;
}

export interface CreateCertDialogData {
  commonName: string;
  countryCode: string;
  state: string;
  city: string;
  organization: string;
  organizationUnit: string
  validDays: string;
  digestAlgorithm: string;
  keyLength: string;
  email: string;
  dnsList: string[];
  ipList: string[];
}

export interface CertificateAuthority {
  id: string;
  base: string
  key: string
  state: string
  keyFile: string
  cert: string
  certFile: string
  city: string
  countryCode: string
  commonName: string;
  subject: string;
  issueTime: number;
  validDays: number;
  organization: string;
  organizationUnit: string;
  certCount: number;
  keyLength: number;
  digestAlgorithm: string;
}

type TrapFunc<T> = () => Observable<T>;
type ErrorFunc<T> = (error: any) => Observable<T>;

export interface Certificate {
  id: string;
  base: string
  key: string
  state: string
  keyFile: string
  cert: string
  certFile: string
  city: string
  countryCode: string
  commonName: string;
  subject: string;
  issueTime: number;
  validDays: number;
  organization: string;
  organizationUnit: string;
  dnsList: string[];
  ipList: string[];
  keyLength: number;
  digestAlgorithm: string;
}
@Injectable({ providedIn: 'root' })
export class CAService {
  private calistURL = '/ca/';  // URL to web api
  httpOptions = {
    headers: new HttpHeaders({ 'Content-Type': 'application/json' })
  };

  constructor(private http: HttpClient) { }

  getCAList(): Observable<CertificateAuthority[]> {
    return this.http.get<CertificateAuthority[]>(this.calistURL)
          .pipe(
            tap(result => this.log(`fetched CA List ${JSON.stringify(result)}`)),
    );
  }

  deleteCA(id:string):Observable<CertificateAuthority> {
    console.log(`Executing deleteCA ${id}`)
    return this.http.delete<CertificateAuthority>(this.calistURL + id)
      .pipe(
                tap(result => this.log(`Delete CA by id ${JSON.stringify(result)}`)),
      );
  }
  deleteCert(caid:string, certid:string):Observable<Certificate> {
    console.log(`Executing deleteCert ${caid}/${certid}`)
    return this.http.delete<Certificate>(this.calistURL + caid + "/cert/" + certid)
      .pipe(
                tap(result => this.log(`Delete Cert by id ${caid}/${certid} result ${JSON.stringify(result)}`)),
      );

  }

  expired(ca?:CertificateAuthority):boolean {
    if(ca == null) {
      return false
    }
    return new Date().getTime() >= ca.issueTime + ca.validDays*3600000*24;
  }
  expiredCert(ca?:Certificate):boolean {
    if(ca == null) {
      return false
    }
    return new Date().getTime() >= ca.issueTime + ca.validDays*3600000*24;
  }
  getCAById(id:string):Observable<CertificateAuthority> {
    return this.http.get<CertificateAuthority>(this.calistURL+ id)
          .pipe(
            tap(result => this.log(`fetched CA by id ${JSON.stringify(result)}`)),
    );
  }

  getCertsByCAId(id:string):Observable<Certificate[]> {
    return this.http.get<Certificate[]>(this.calistURL+ id + "/cert")
          .pipe(
            tap(result => this.log(`fetched CA by id ${JSON.stringify(result)}`)),
    );
  }

  createCA(data:CreateCADialogData):Observable<CertificateAuthority> {
    return this.http.put<CertificateAuthority>(this.calistURL + "new", data)
      .pipe(
        tap(result => this.log(`create CA with ${JSON.stringify(data)} result ${JSON.stringify(result)}`)),
      );
  }

  createCert(caid:string, data:CreateCertDialogData):Observable<Certificate> {
    return this.http.put<Certificate>(this.calistURL + caid + "/new", data)
      .pipe(
        tap(result => this.log(`create Cert in CA ${caid} with ${JSON.stringify(data)} result ${JSON.stringify(result)}`)),
      );
  }


  getCertByCAAndCertId(caid:string, certid:string):Observable<Certificate> {
    return this.http.get<Certificate>(this.calistURL + caid + "/cert/" + certid)
      .pipe(
        tap(result => this.log(`fetched Cert By ID ${caid} + ${certid}: ${JSON.stringify(result)}`)),
    );
  }

  private log(message: string) {
    console.log(`CAService: ${message}`);
  }

  private handleError<T>(operation = 'operation', result?: T) {
    return (error: any): Observable<T> => {
      console.error(error); // log to console instead
      this.log(`${operation} failed: ${error.message}`);
      return of(result as T);
    };
  }
}
