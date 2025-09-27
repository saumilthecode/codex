
void FUN_08021d60(int param_1,uint param_2,uint param_3)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  undefined4 unaff_r4;
  undefined4 unaff_r5;
  undefined4 in_lr;
  undefined8 uVar7;
  
  uVar7 = CONCAT44(param_2,param_1);
  uVar5 = *(uint *)(param_1 + 4);
  if (uVar5 < param_2) {
    uVar7 = FUN_08010508(DAT_08021d98,DAT_08021d9c,param_2);
  }
  iVar4 = (int)((ulonglong)uVar7 >> 0x20);
  piVar1 = (int *)uVar7;
  if (param_3 == 0xffffffff) {
    iVar6 = *piVar1;
    *(int *)(param_1 + 4) = iVar4;
    *(undefined1 *)(iVar6 + iVar4) = 0;
  }
  else if (param_3 != 0) {
    uVar2 = uVar5 - iVar4;
    if (param_3 <= uVar5 - iVar4) {
      uVar2 = param_3;
    }
    iVar6 = piVar1[1] - (iVar4 + uVar2);
    if ((iVar6 != 0) && (uVar2 != 0)) {
      iVar3 = *piVar1;
      FUN_08017d80(iVar4 + iVar3,iVar4 + uVar2 + iVar3,iVar6,iVar3,uVar5,unaff_r4,unaff_r5,in_lr);
    }
    iVar4 = piVar1[1];
    piVar1[1] = iVar4 - uVar2;
    *(undefined1 *)(*piVar1 + (iVar4 - uVar2)) = 0;
    return;
  }
  return;
}

