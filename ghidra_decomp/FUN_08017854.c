
void FUN_08017854(int *param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  
  uVar1 = FUN_080105ba(*(int *)(*param_1 + -0xc) + (int)param_1);
  while( true ) {
    if (param_2 < 1) {
      return;
    }
    iVar2 = FUN_08017c78(*(undefined4 *)((int)param_1 + *(int *)(*param_1 + -0xc) + 0x78),uVar1);
    if (iVar2 == -1) break;
    param_2 = param_2 + -1;
  }
  FUN_08010584(*(int *)(*param_1 + -0xc) + (int)param_1,1);
  return;
}

