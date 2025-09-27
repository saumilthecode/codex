
undefined4 FUN_0802e608(int param_1)

{
  ushort uVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  int *piVar6;
  
  iVar3 = *DAT_0802e634;
  piVar6 = DAT_0802e634;
  if ((iVar3 != 0) && (piVar6 = *(int **)(iVar3 + 0x34), piVar6 == (int *)0x0)) {
    FUN_08025ec4();
  }
  uVar5 = *(uint *)(param_1 + 100);
  uVar4 = (uint)*(short *)(param_1 + 0xc);
  if ((int)(uVar5 << 0x1f) < 0) {
    if (-1 < (int)(uVar4 << 0x12)) goto LAB_0802e598;
    uVar5 = uVar5 << 0x12;
    if (-1 < (int)uVar5) {
      return 0xffffffff;
    }
LAB_0802e5a4:
    uVar2 = FUN_0802e4f4(iVar3,param_1,uVar4,uVar5,piVar6);
    uVar5 = *(uint *)(param_1 + 100);
  }
  else {
    if ((int)(uVar4 << 0x16) < 0) {
      if ((int)(uVar4 << 0x12) < 0) {
        uVar5 = uVar5 << 0x12;
        if (-1 < (int)uVar5) {
          uVar1 = *(ushort *)(param_1 + 0xc);
          uVar2 = 0xffffffff;
          goto joined_r0x0802e5d2;
        }
        goto LAB_0802e5a4;
      }
LAB_0802e598:
      uVar4 = uVar4 | 0x2000;
      uVar5 = uVar5 | 0x2000;
      *(short *)(param_1 + 0xc) = (short)uVar4;
      *(uint *)(param_1 + 100) = uVar5;
      goto LAB_0802e5a4;
    }
    FUN_08028650(*(undefined4 *)(param_1 + 0x58));
    uVar4 = (uint)*(short *)(param_1 + 0xc);
    uVar5 = *(uint *)(param_1 + 100);
    if (-1 < (int)(uVar4 << 0x12)) goto LAB_0802e598;
    if ((int)(uVar5 << 0x12) < 0) goto LAB_0802e5a4;
    uVar2 = 0xffffffff;
  }
  if ((int)(uVar5 << 0x1f) < 0) {
    return uVar2;
  }
  uVar1 = *(ushort *)(param_1 + 0xc);
joined_r0x0802e5d2:
  if ((int)((uint)uVar1 << 0x16) < 0) {
    return uVar2;
  }
  FUN_08028654(*(undefined4 *)(param_1 + 0x58));
  return uVar2;
}

