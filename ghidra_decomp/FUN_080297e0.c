
void FUN_080297e0(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  int local_30;
  int aiStack_2c [2];
  
  uVar4 = FUN_0802969c(param_1,&local_30);
  iVar3 = (int)((ulonglong)uVar4 >> 0x20);
  uVar5 = FUN_0802969c(param_2,aiStack_2c);
  iVar2 = (int)((ulonglong)uVar5 >> 0x20);
  iVar1 = (local_30 - aiStack_2c[0]) + (*(int *)(param_1 + 0x10) - *(int *)(param_2 + 0x10)) * 0x20;
  if (iVar1 < 1) {
    iVar2 = iVar2 + iVar1 * -0x100000;
  }
  else {
    iVar3 = iVar3 + iVar1 * 0x100000;
  }
  FUN_0800647c((int)uVar4,iVar3,(int)uVar5,iVar2);
  return;
}

