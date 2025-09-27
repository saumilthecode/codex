
void FUN_08017898(int *param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  
  iVar1 = FUN_08017c9a(*(undefined4 *)((int)param_1 + *(int *)(*param_1 + -0xc) + 0x78));
  if (param_3 != iVar1) {
    FUN_08010584(*(int *)(*param_1 + -0xc) + (int)param_1,1);
    return;
  }
  return;
}

