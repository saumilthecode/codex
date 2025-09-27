
void FUN_0800a818(int *param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  undefined4 uStack_c;
  
  iVar1 = *param_1 + -0xc;
  iVar2 = *(int *)(*param_1 + -4);
  uStack_c = param_2;
  if (iVar2 < 1) {
    FUN_0800a74c(iVar1,0,param_3,iVar2,param_1);
  }
  else {
    FUN_0800a7fc(iVar1,&uStack_c);
    *param_1 = DAT_0800a840;
  }
  return;
}

