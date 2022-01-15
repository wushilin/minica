import {Component} from '@angular/core';
import {MatSnackBar} from '@angular/material/snack-bar';

/**
 * @title Basic progress-spinner
 */
@Component({
  selector: 'app-toaster',
  templateUrl: 'toaster.component.html',
  styleUrls: ['./toaster.component.css']
})
export class ToasterComponent {
  constructor(private _snackBar: MatSnackBar) {
  }

  say(message: string, action: string) {
    this._snackBar.open(message, action);
  }
}
