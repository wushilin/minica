import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { CalistComponent, CreateCADialog, ImportCADialog, ViewCertDialog} from './calist/calist.component';
import { CadetailComponent,CreateCertDialog} from './cadetail/cadetail.component';
import { CertDetailComponent } from './certdetail/certdetail.component';
import { HttpClientModule } from '@angular/common/http';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { RouterModule, Routes } from '@angular/router';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import {MatFormFieldModule} from '@angular/material/form-field';
import {FormsModule, ReactiveFormsModule} from '@angular/forms';
import { MatSelectModule } from '@angular/material/select';
import { MaterialModule } from './material/material.module';
import { ConfirmDialogComponent } from './confirmdialog/confirmdialog.component';
import { SpinnerComponent } from './spinner/spinner.component';
import { ToasterComponent } from './toaster/toaster.component';
@NgModule({
  declarations: [
    AppComponent,
    CalistComponent,
    CadetailComponent,
    CertDetailComponent,
    CreateCADialog,
    ConfirmDialogComponent,
    CreateCertDialog,
    SpinnerComponent,
    ToasterComponent,
    ImportCADialog,
    ViewCertDialog
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    BrowserAnimationsModule,
    RouterModule,
    MatCardModule,
    MatButtonModule,
    MatFormFieldModule,
    FormsModule,
    ReactiveFormsModule,
    MatSelectModule,
    MaterialModule,
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
