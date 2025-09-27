
void FUN_08009214(undefined4 *param_1,int *param_2,undefined4 param_3)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  int *piStack_14;
  undefined4 uStack_10;
  
  puVar3 = param_1;
  piStack_14 = param_2;
  uStack_10 = param_3;
  if ((code *)param_1[6] != (code *)0x0) {
    (*(code *)param_1[6])();
  }
  iVar2 = *(int *)(*param_2 + -4);
  if (iVar2 < 0) {
    uVar1 = FUN_0800b074(*param_2 + -0xc,&piStack_14,0,iVar2,puVar3);
  }
  else {
    uVar1 = FUN_0800b060();
  }
  *param_1 = uVar1;
  param_1[1] = *(undefined4 *)(*param_2 + -0xc);
  param_1[6] = DAT_08009250;
  return;
}

