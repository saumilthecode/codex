
uint FUN_08025738(undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  longlong lVar6;
  
  puVar1 = DAT_080257d0;
  lVar6 = FUN_08024b78(*DAT_080257d0,param_1,param_2,DAT_080257d4);
  uVar4 = (uint)((ulonglong)lVar6 >> 0x20);
  uVar2 = (undefined4)lVar6;
  iVar3 = FUN_0800675c(uVar2,uVar4,uVar2,uVar4);
  if (iVar3 != 0) {
    if (lVar6 < 0) {
      iVar3 = FUN_08028690(DAT_080257d8);
      return iVar3 + 0x80000000;
    }
    uVar4 = FUN_08028690(DAT_080257d8);
    return uVar4;
  }
  uVar5 = FUN_080067c8(uVar2,uVar4);
  iVar3 = FUN_08006954(uVar5 & 0x7fffffff,DAT_080257dc);
  if ((iVar3 == 0) && (iVar3 = FUN_08006918(uVar5 & 0x7fffffff,DAT_080257dc), iVar3 == 0)) {
    iVar3 = FUN_0800675c(uVar2,uVar4 & 0x7fffffff,0xffffffff,DAT_080257e0);
    if ((iVar3 != 0) ||
       (iVar3 = FUN_08006720(uVar2,uVar4 & 0x7fffffff,0xffffffff,DAT_080257e0), iVar3 != 0))
    goto LAB_080257c8;
  }
  if ((uVar5 & 0x7f800000) != 0) {
    return uVar5;
  }
  if ((DAT_080257e4 & uVar4) == 0) {
    return uVar5;
  }
LAB_080257c8:
  *(undefined4 *)*puVar1 = 0x22;
  return uVar5;
}

