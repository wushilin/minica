import { Component, OnInit, Inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { Location } from '@angular/common';
import { CertificateAuthority, CAService, ImportCADialogData, ViewCertDialogData, CreateCADialogData,withLoading,trap, reportError, reportSuccess } from '../minica.service';
import { MatDialog, MatDialogRef, MAT_DIALOG_DATA} from '@angular/material/dialog';
import { ConfirmDialogComponent } from '../confirmdialog/confirmdialog.component';
import {MatSnackBar} from '@angular/material/snack-bar';

@Component({
  selector: 'app-calist',
  templateUrl: './calist.component.html',
  styleUrls: ['./calist.component.css']
})
export class CalistComponent implements OnInit {
    importCAData: ImportCADialogData = {
      cert: "",
      key: "",
      password: "changeit"
    };

    viewCertData: ViewCertDialogData = {
      cert: "",
      info: new Map<string, string>()
    };

    createCAData: CreateCADialogData = {
      commonName: "",
      countryCode: "",
      state: "",
      city: "",
      organization: "",
      organizationUnit: "",
      validDays: "365",
      digestAlgorithm: "sha512",
      keyLength: "4096",
      password: "changeit",
    };
    calist: CertificateAuthority[] = []

    constructor(
      private route: ActivatedRoute,
      public caService: CAService,
      private location: Location,
      public dialog: MatDialog,
      private _snackBar: MatSnackBar
    ) {}

  ngOnInit(): void {
    this.loadCSRFToken()
  }

  loadCSRFToken() {
      console.log("Loading csrf")
      this.caService.loadCSRF().subscribe(result =>{
        console.log(`loaded csrf token`)
        this.getCAList()
      })
  }

  deleteCA(id:string, name:string) {
    const dialogRef = this.dialog.open(ConfirmDialogComponent, {
      width: '500px',
      data: {
        title:"Are you sure?",
        messages: [`You are about to delete Certicate Authority with:`,`Subject: ${name}`,`ID: ${id}`, `---------`, `This can't be undone.`]
      }
    });
    dialogRef.afterClosed().subscribe(result => {
      if(result) {
        console.log(`Deleting CA ${id}`)
        withLoading(
          ()=>this.caService.deleteCA(id),
          (error)=>reportError(this._snackBar, "Failed to delete CA", "Dismiss")
          ).subscribe(result => {
          if(result.id)
             reportSuccess(this._snackBar, "Successfully deleted CA", "Dismiss");
          this.getCAList();
        });
      }
    });
  }
  openViewCertDialog(): void {
    const dialogRef = this.dialog.open(ViewCertDialog, {
      width: '80%',
      data: this.viewCertData,
    });
  }

  openImportDialog(): void {
    const dialogRef = this.dialog.open(ImportCADialog, {
      width: '800px',
      data: this.importCAData,
    });

    dialogRef.afterClosed().subscribe(result => {
      if(result) {
        console.log('The dialog was closed');
        this.importCAData = result;
        console.log(JSON.stringify(result));
        withLoading(
          ()=>this.caService.importCA(result),
          (error)=>reportError(this._snackBar, "Failed to import CA", "Dismiss")
          ).subscribe(what => {
              if(what.id) {
                reportSuccess(this._snackBar, "Successfully imported CA", "Dismiss");
              }
              this.getCAList();
          });
      }
    });
  }

  openCreateDialog(): void {
    const dialogRef = this.dialog.open(CreateCADialog, {
      width: '500px',
      data: this.createCAData,
    });

    dialogRef.afterClosed().subscribe(result => {
      if(result) {
        console.log('The dialog was closed');
        this.createCAData = result;
        console.log(JSON.stringify(result));
        withLoading(
          ()=>this.caService.createCA(result),
          (error)=>reportError(this._snackBar, "Failed to create CA", "Dismiss")
          ).subscribe(what => {
              if(what.id) {
                reportSuccess(this._snackBar, "Successfully created CA", "Dismiss");
              }
              this.getCAList();
          });
      }
    });
  }

  getCAList() {
    withLoading(
      ()=>this.caService.getCAList()
    ).subscribe(what => this.calist = what);
  }
}

@Component({
  selector: 'create-ca-dialog',
  templateUrl: 'create-ca-dialog.html',
  styleUrls: ['./calist.component.css']
})
export class CreateCADialog {
  constructor(
    public dialogRef: MatDialogRef<CreateCADialog>,
    @Inject(MAT_DIALOG_DATA) public data: CreateCADialogData,
  ) {}

  onNoClick(): void {
    this.dialogRef.close();
  }
}

@Component({
  selector: 'import-ca-dialog',
  templateUrl: 'import-ca-dialog.html',
  styleUrls: ['./calist.component.css']
})
export class ImportCADialog {
  constructor(
    public dialogRef: MatDialogRef<ImportCADialog>,
    @Inject(MAT_DIALOG_DATA) public data: ImportCADialogData,
  ) {}

  onNoClick(): void {
    this.dialogRef.close();
  }
}
@Component({
  selector: 'view-cert-dialog',
  templateUrl: 'view-cert-dialog.html',
  styleUrls: ['./calist.component.css']
})
export class ViewCertDialog {
  constructor(
    public dialogRef: MatDialogRef<ViewCertDialog>,
    @Inject(MAT_DIALOG_DATA) public data: ViewCertDialogData,
    public caService: CAService,
    private _snackBar: MatSnackBar,

  ) {}

  onNoClick(): void {
    this.data.cert = "";
    this.data.info = new Map<string, string>();
    this.dialogRef.close();
  }
  asIsOrder<T>(a:T, b:T) {
    return 1;
  }

  decodeCert():void {
    console.log(this.data.cert)
    withLoading(
      ()=>this.caService.inspectCert(this.data),
      (error)=>reportError(this._snackBar, "Failed to inspect cert", "Dismiss")
      ).subscribe(result => {
      if(result.info) {
         reportSuccess(this._snackBar, "Successfully inspected cert", "Dismiss");
         console.log(JSON.stringify(result));
         this.data.info = result.info;
      }
    });
  }
}
