
int FUN_08007eac(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  
  iVar1 = FUN_08007f18();
  uVar5 = FUN_08007dce(param_1,param_1 + -0x20);
  if ((int)uVar5 == 0) {
    if (*(int *)(iVar1 + 8) != 0) {
      FUN_08008438();
      iVar1 = FUN_08007f18();
      iVar2 = *(int *)(iVar1 + 8);
      if (iVar2 == 0) {
        FUN_08008438(iVar1,iVar1);
      }
      iVar4 = iVar2 + 0x20;
      uVar5 = FUN_08007dce(iVar4);
      iVar1 = (int)((ulonglong)uVar5 >> 0x20);
      if ((int)uVar5 == 0) {
        *(undefined4 *)(iVar1 + 8) = 0;
      }
      else {
        iVar3 = *(int *)(iVar2 + 0x1c) + -1;
        *(int *)(iVar2 + 0x1c) = iVar3;
        if (iVar3 == 0) {
          *(undefined4 *)(iVar1 + 8) = *(undefined4 *)(iVar2 + 0x18);
          *(undefined4 *)(iVar2 + 0x18) = 0;
        }
      }
      return iVar4;
    }
  }
  else {
    iVar2 = *(int *)(param_1 + -4) + 1;
    *(int *)(param_1 + -4) = iVar2;
    if (iVar2 != 1) {
      return 1;
    }
    *(undefined4 *)(param_1 + -8) = *(undefined4 *)(iVar1 + 8);
  }
  *(int *)(iVar1 + 8) = (int)((ulonglong)uVar5 >> 0x20);
  return 1;
}

