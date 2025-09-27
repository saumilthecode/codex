
void FUN_08003eb4(int *param_1)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *param_1;
  uVar2 = *(uint *)(iVar3 + 4) & 0xffffff9f;
  *(uint *)(iVar3 + 4) = uVar2;
  uVar1 = FUN_0800061c(param_1,uVar2,*(undefined1 *)(iVar3 + 0xc));
  if (param_1[1] == 0x104) {
    if (param_1[2] == 0x8000) {
      *(uint *)*param_1 = *(uint *)*param_1 & 0xffffffbf;
      iVar3 = FUN_08002374(param_1,0x80,0,uVar1);
    }
    else if (param_1[2] == 0x400) {
      *(uint *)*param_1 = *(uint *)*param_1 & 0xffffffbf;
      iVar3 = FUN_08002374(param_1,1,0,uVar1);
    }
    else {
      iVar3 = FUN_08002374(param_1,0x80,0,uVar1);
    }
  }
  else {
    iVar3 = FUN_08002374(param_1,1,0,uVar1);
  }
  if (iVar3 != 0) {
    param_1[0x15] = param_1[0x15] | 0x20;
    param_1[0x15] = param_1[0x15] | 0x20;
  }
  *(undefined1 *)((int)param_1 + 0x51) = 1;
  if (*(int *)(*param_1 + 8) << 0x1b < 0) {
    param_1[0x15] = param_1[0x15] | 2;
    *(undefined4 *)(*param_1 + 8) = 0xffef;
    FUN_0800363c(param_1);
    return;
  }
  if (param_1[0x15] == 0) {
    FUN_08003604(param_1);
    return;
  }
  FUN_0800363c();
  return;
}

