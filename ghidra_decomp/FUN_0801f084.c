
int FUN_0801f084(int param_1)

{
  int *piVar1;
  int extraout_r1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  
  piVar1 = (int *)FUN_08007f18();
  iVar4 = *piVar1;
  uVar5 = FUN_0801f04a(param_1,param_1 + -0x20);
  iVar2 = (int)((ulonglong)uVar5 >> 0x20);
  if ((int)uVar5 == 0) {
    if (iVar4 != 0) {
      FUN_08008438();
      iVar2 = extraout_r1;
    }
    *piVar1 = iVar2;
  }
  else {
    iVar3 = *(int *)(param_1 + -0xc);
    if (iVar3 < 0) {
      iVar3 = -iVar3;
    }
    *(int *)(param_1 + -0xc) = iVar3 + 1;
    piVar1[1] = piVar1[1] + -1;
    if (iVar4 != iVar2) {
      *(int *)(param_1 + -0x10) = iVar4;
      *piVar1 = iVar2;
    }
    iVar4 = *(int *)(param_1 + 0x24);
    FUN_0802b9b6(param_1);
  }
  return iVar4;
}

