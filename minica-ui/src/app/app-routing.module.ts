import { NgModule } from '@angular/core';
import { RouterModule, Routes, UrlSegment} from '@angular/router';
import { CalistComponent } from './calist/calist.component';
import { CadetailComponent } from './cadetail/cadetail.component';
import { CertDetailComponent } from './certdetail/certdetail.component';

const routes: Routes = [
  { path: '', redirectTo: '/calist', pathMatch: 'full' },
  { matcher: (url) => {
          console.log(url)
          if(url.length === 1 && url[0].path === "cadetail") {
            return {
              consumed: url,
              posParams: {
                id: new UrlSegment("", {})
              }
            }
          };
          if (url.length === 2 && url[0].path === "cadetail") {
            return {
              consumed: url,
              posParams: {
                id: new UrlSegment(url[1].path, {})
              }
            };
          }
          return null;
        }, component: CadetailComponent},
  { matcher: (url) => {
      console.log(JSON.stringify(url));
      if(url.length === 3 && url[0].path === "certdetail") {
                return {
                  consumed: url,
                  posParams: {
                    caid: new UrlSegment(url[1].path, {}),
                    certid: new UrlSegment(url[2].path, {})
                  }
                }
              };
              return null;
  }, component: CertDetailComponent},
  { path: 'calist', component: CalistComponent },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
