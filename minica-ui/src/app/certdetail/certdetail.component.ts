import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from "@angular/router";
import { CAService, CertificateAuthority, Certificate, withLoading, reportError, reportSuccess, trap} from "../minica.service";
import {FormControl} from '@angular/forms';
import {MatSnackBar} from '@angular/material/snack-bar';
import { MatDialog } from '@angular/material/dialog';
import { ConfirmDialogComponent } from '../confirmdialog/confirmdialog.component';
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
  renewDays:number = 365

  constructor(private route: ActivatedRoute, public caService:CAService,private _snackBar: MatSnackBar, public dialog: MatDialog) { }

  ngOnInit(): void {
    this.route.params.forEach(param => {
  	  this.caid = param["caid"];
  	  this.certid = param["certid"];
  	  } );
      this.refreshData()
  }

  refreshData() {
  	if(this.caid && this.certid) {
      withLoading(()=>this.caService.getCAById(`${this.caid}`)).subscribe(what => this.cadetail = what);
      withLoading(()=>this.caService.getCertByCAAndCertId(`${this.caid}`, `${this.certid}`)).subscribe(what => this.certdetail = what);
    }
  }
  doRenew() {
    console.log(`Doing renew!`);
    const dialogRef = this.dialog.open(ConfirmDialogComponent, {
      width: '500px',
      data: {
        title:"Are you sure?",
        messages: [`You are about to renew Certificate by ${this.renewDays} days from now. `,
        `The private key remain as is.`,
        `The certificate will be replaced.`,
        `---------`, `This can't be undone.`]
      }
    });
    let caid = this.caid.toString()
    let certid = this.certid.toString()
    dialogRef.afterClosed().subscribe(result => {
      if(result) {
        console.log(`Renewing Cert ${this.certid} (${this.caid})`)
        withLoading(
          ()=>this.caService.renewCert(caid, certid, this.renewDays),
          (error) => reportError(this._snackBar, "Failed to renew Certificate", "Dismiss")
        ).subscribe(result => {
          if(result.id) {
            reportSuccess(this._snackBar, "Successfully renewed cert", "Dismiss");
          }
          this.refreshData();
        });
      }
    });
  }
}
