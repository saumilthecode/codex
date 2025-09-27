
void FUN_0800aa82(int *param_1,uint param_2)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uStack_14;
  
  iVar3 = *param_1;
  uVar2 = param_2;
  if ((*(uint *)(iVar3 + -8) < param_2) || (uVar2 = *(uint *)(iVar3 + -8), 0 < *(int *)(iVar3 + -4))
     ) {
    uStack_14 = param_2;
    iVar1 = FUN_0800a648(param_1);
    iVar3 = FUN_0800aa50(iVar3 + -0xc,&uStack_14,uVar2 - iVar1);
    FUN_0800a7fc(*param_1 + -0xc,&uStack_14);
    *param_1 = iVar3;
  }
  return;
}

