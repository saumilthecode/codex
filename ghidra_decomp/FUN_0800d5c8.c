
void FUN_0800d5c8(int param_1,uint param_2,uint param_3)

{
  int *piVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 unaff_r4;
  undefined4 unaff_r5;
  undefined4 in_lr;
  undefined8 uVar7;
  
  uVar7 = CONCAT44(param_2,param_1);
  uVar3 = *(uint *)(param_1 + 4);
  if (uVar3 < param_2) {
    uVar7 = FUN_08010508(DAT_0800d600,DAT_0800d604,param_2);
  }
  iVar6 = (int)((ulonglong)uVar7 >> 0x20);
  piVar1 = (int *)uVar7;
  if (param_3 == 0xffffffff) {
    iVar4 = *piVar1;
    *(int *)(param_1 + 4) = iVar6;
    *(undefined1 *)(iVar4 + iVar6) = 0;
  }
  else if (param_3 != 0) {
    uVar2 = uVar3 - iVar6;
    if (param_3 <= uVar3 - iVar6) {
      uVar2 = param_3;
    }
    iVar4 = piVar1[1] - (iVar6 + uVar2);
    if ((iVar4 != 0) && (uVar2 != 0)) {
      iVar5 = *piVar1;
      FUN_08017d80(iVar6 + iVar5,iVar6 + uVar2 + iVar5,iVar4,iVar5,uVar3,unaff_r4,unaff_r5,in_lr);
    }
    iVar6 = piVar1[1];
    piVar1[1] = iVar6 - uVar2;
    *(undefined1 *)(*piVar1 + (iVar6 - uVar2)) = 0;
    return;
  }
  return;
}

