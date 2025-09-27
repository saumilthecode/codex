
void FUN_08009150(undefined4 *param_1,int *param_2,undefined4 param_3)

{
  undefined4 uVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 *puVar4;
  int *piStack_14;
  undefined4 uStack_10;
  
  puVar4 = param_1;
  piStack_14 = param_2;
  uStack_10 = param_3;
  if ((code *)param_1[6] != (code *)0x0) {
    (*(code *)param_1[6])();
  }
  iVar3 = *(int *)(*param_2 + -4);
  if (iVar3 < 0) {
    uVar1 = FUN_0800aa50(*param_2 + -0xc,&piStack_14,0,iVar3,puVar4);
  }
  else {
    uVar1 = FUN_0800aa3c();
  }
  *param_1 = uVar1;
  uVar1 = DAT_0800918c;
  uVar2 = FUN_0800914a(*param_2);
  param_1[6] = uVar1;
  param_1[1] = uVar2;
  return;
}

