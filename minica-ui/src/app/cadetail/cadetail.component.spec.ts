import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CadetailComponent } from './cadetail.component';

describe('CadetailComponent', () => {
  let component: CadetailComponent;
  let fixture: ComponentFixture<CadetailComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ CadetailComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(CadetailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
