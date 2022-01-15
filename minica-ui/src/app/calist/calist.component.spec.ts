import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CalistComponent } from './calist.component';

describe('CalistComponent', () => {
  let component: CalistComponent;
  let fixture: ComponentFixture<CalistComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ CalistComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(CalistComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
