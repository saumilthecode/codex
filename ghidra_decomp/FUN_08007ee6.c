
int FUN_08007ee6(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  
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

