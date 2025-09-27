
void FUN_0800ae80(int *param_1,int param_2,int param_3,int param_4)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int *piVar5;
  int iStack_2c;
  int iStack_28;
  
  piVar5 = param_1;
  iStack_2c = param_2;
  iStack_28 = param_3;
  iVar1 = FUN_0800acd4();
  iVar4 = param_3 + param_2;
  uVar3 = (param_4 - param_3) + iVar1;
  iVar1 = iVar1 - iVar4;
  iVar2 = *param_1;
  if ((*(uint *)(iVar2 + -8) < uVar3) || (0 < *(int *)(iVar2 + -4))) {
    iVar2 = FUN_0800add0(uVar3,*(uint *)(iVar2 + -8),&iStack_2c);
    if (param_2 != 0) {
      FUN_0800ac7a(iVar2 + 0xc,*param_1,param_2);
    }
    if (iVar1 != 0) {
      FUN_0800ac7a(iVar2 + (param_4 + param_2) * 4 + 0xc,*param_1 + iVar4 * 4,iVar1);
    }
    FUN_0800ae64(*param_1 + -0xc,&iStack_2c);
    *param_1 = iVar2 + 0xc;
  }
  else if ((iVar1 != 0) && (param_4 != param_3)) {
    FUN_0800ac92(iVar2 + (param_4 + param_2) * 4,iVar2 + iVar4 * 4,iVar1,*(int *)(iVar2 + -4),piVar5
                );
  }
  FUN_0800adb8(*param_1 + -0xc,uVar3);
  return;
}

