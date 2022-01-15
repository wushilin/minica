import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from "@angular/router";
import { CAService, CertificateAuthority, Certificate, withLoading, reportError, reportSuccess, trap} from "../minica.service";
import {FormControl} from '@angular/forms';
import {MatSnackBar} from '@angular/material/snack-bar';

@Component({
  selector: 'app-certdetail',
  templateUrl: './certdetail.component.html',
  styleUrls: ['./certdetail.component.css']
})
export class CertDetailComponent implements OnInit {
  caid:String = ""
  certid:String = ""
  cadetail:CertificateAuthority | undefined
  certdetail:Certificate | undefined

  constructor(private route: ActivatedRoute, public caService:CAService,private _snackBar: MatSnackBar) { }

  ngOnInit(): void {
    this.route.params.forEach(param => {
  	  this.caid = param["caid"];
  	  this.certid = param["certid"];
  	  } );
  	if(this.caid && this.certid) {
      withLoading(()=>this.caService.getCAById(`${this.caid}`)).subscribe(what => this.cadetail = what);
      withLoading(()=>this.caService.getCertByCAAndCertId(`${this.caid}`, `${this.certid}`)).subscribe(what => this.certdetail = what);
    }
  }
}
