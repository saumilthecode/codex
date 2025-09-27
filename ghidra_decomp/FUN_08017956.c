
void FUN_08017956(int *param_1,int *param_2)

{
  int iVar1;
  
  iVar1 = *(int *)((int)param_2 + *(int *)(*param_2 + -0xc) + 0x78);
  *param_1 = iVar1;
  *(bool *)(param_1 + 1) = iVar1 == 0;
  return;
}

