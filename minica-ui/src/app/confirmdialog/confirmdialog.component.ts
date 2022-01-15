import { MatDialog, MatDialogRef, MAT_DIALOG_DATA} from '@angular/material/dialog';
import { Component, OnInit, Inject } from '@angular/core';

export interface ConfirmDialogData {
  title: string;
  messages: string[];
}

@Component({
  selector: 'confirm-dialog',
  templateUrl: 'confirmdialog.component.html',
  styleUrls: ['./confirmdialog.component.css']
})
export class ConfirmDialogComponent {
  constructor(
    public dialogRef: MatDialogRef<ConfirmDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: ConfirmDialogData,
  ) {}
}
