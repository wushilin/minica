import { Component, OnInit, Inject } from '@angular/core';
import { ActivatedRoute } from "@angular/router";
import { CAService, CertificateAuthority, Certificate,CreateCertDialogData, reportError, reportSuccess, withLoading} from "../minica.service";
import {FormControl} from '@angular/forms';
import {MatSnackBar} from '@angular/material/snack-bar';
import { MatDialog, MatDialogRef, MAT_DIALOG_DATA} from '@angular/material/dialog';
import {COMMA, ENTER} from '@angular/cdk/keycodes';
import {MatChipInputEvent} from '@angular/material/chips';
import { ConfirmDialogComponent } from '../confirmdialog/confirmdialog.component';
import { Observable, of } from 'rxjs';

@Component({
  selector: 'app-cadetail',
  templateUrl: './cadetail.component.html',
  styleUrls: ['./cadetail.component.css']
})
export class CadetailComponent implements OnInit {
  id:String = ""
  createCertData: CreateCertDialogData = {
    commonName: "",
    countryCode: "",
    state: "",
    city: "",
    organization: "",
    organizationUnit: "",
    validDays: "365",
    digestAlgorithm: "sha512",
    keyLength: "4096",
    email: "",
    dnsList: [],
    ipList: [],
  };
  cadetail:CertificateAuthority | undefined
  certList:Certificate[] = []
  disableSelect = new FormControl(false);

  constructor(private route: ActivatedRoute, public caService:CAService, public dialog: MatDialog, private _snackBar: MatSnackBar) { }

  ngOnInit(): void {
    this.route.params.forEach(param => {
  	  this.id = param["id"]; } );
  	if(this.id) {
      this.reloadData();
    }
  }

  deleteCert(ca:CertificateAuthority, cert:Certificate) {
    const dialogRef = this.dialog.open(ConfirmDialogComponent, {
      width: '500px',
      data: {
        title:"Are you sure?",
        messages: [`You are about to delete Certicate  with:`,`Subject: ${cert.subject}`,`ID: ${cert.id}`,
        `from CA ${ca.commonName}, CAID ${ca.id}`,
        `---------`, `This can't be undone.`]
      }
    });
    dialogRef.afterClosed().subscribe(result => {
      if(result) {
        console.log(`Deleting Cert ${cert.id}`)
        withLoading(
          ()=>this.caService.deleteCert(ca.id, cert.id),
          (error) => reportError(this._snackBar, "Failed to delete Certificate", "Dismiss")
        ).subscribe(result => {
          if(result.id) {
            reportSuccess(this._snackBar, "Successfully created cert", "Dismiss");
          }
          this.reloadData();
        });
      }
    });
  }

  reloadData() : void{
    if(this.id) {
      withLoading(()=>this.caService.getCAById(`${this.id}`)).subscribe(what => this.cadetail = what);
      withLoading(()=>this.caService.getCertsByCAId(`${this.id}`)).subscribe(what => this.certList = what);
    }
  }
  openCreateDialog(): void {
    const dialogRef = this.dialog.open(CreateCertDialog, {
      width: '500px',
      data: this.createCertData,
    });

    dialogRef.afterClosed().subscribe(result => {
      if(this.cadetail && result) {
        console.log('The dialog was closed');
        this.createCertData = result;
        console.log(JSON.stringify(result));
        withLoading(()=>this.caService.createCert(this.cadetail!.id, result),
          (error)=>reportError(this._snackBar, "Failed to create cert", "Dismiss")).subscribe(result => {
          if(result.id) {
            reportSuccess(this._snackBar, "Successfully created cert", "Dismiss");
          }
          this.reloadData();
          }
        );
      }
    });
  }
}

@Component({
  selector: 'create-cert-dialog',
  templateUrl: 'create-cert-dialog.html',
  styleUrls: ['./cadetail.component.css']
})
export class CreateCertDialog {
  readonly separatorKeysCodes = [ENTER, COMMA] as const;
  addOnBlur = true;
  addDNS(event: MatChipInputEvent): void {
    const value = (event.value || '').trim();

    // Add our fruit
    if (value) {
      this.data.dnsList.push(value);
    }

    // Clear the input value
    event.chipInput!.clear();
  }

  removeDNS(dns: string): void {
    const index = this.data.dnsList.indexOf(dns);

    if (index >= 0) {
      this.data.dnsList.splice(index, 1);
    }
  }
  addIP(event: MatChipInputEvent): void {
    const value = (event.value || '').trim();

    // Add our fruit
    if (value) {
      this.data.ipList.push(value);
    }

    // Clear the input value
    event.chipInput!.clear();
  }

  removeIP(ip: string): void {
    const index = this.data.ipList.indexOf(ip);

    if (index >= 0) {
      this.data.ipList.splice(index, 1);
    }
  }
  constructor(
    public dialogRef: MatDialogRef<CreateCertDialog>,
    @Inject(MAT_DIALOG_DATA) public data: CreateCertDialogData,
  ) {}

  onNoClick(): void {
    this.dialogRef.close();
  }
}
