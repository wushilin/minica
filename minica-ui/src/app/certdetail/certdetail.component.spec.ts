import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CertDetailComponent } from './certdetail.component';

describe('CertdetailComponent', () => {
  let component: CertDetailComponent;
  let fixture: ComponentFixture<CertDetailComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ CertDetailComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(CertDetailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
