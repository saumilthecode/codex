
void FUN_0800add0(uint param_1,undefined4 param_2)

{
  int iVar1;
  uint uVar2;
  undefined8 uVar3;
  
  uVar3 = CONCAT44(param_2,param_1);
  if (0xffffffe < param_1) {
    uVar3 = FUN_08010502(DAT_0800ae24);
  }
  uVar2 = (uint)((ulonglong)uVar3 >> 0x20);
  if ((uVar2 < (uint)uVar3) && ((uint)uVar3 < uVar2 << 1)) {
    param_1 = uVar2 << 1;
  }
  iVar1 = (param_1 + 4) * 4;
  if ((0x1000 < iVar1 + 0x10U) && (uVar2 < param_1)) {
    param_1 = param_1 + (0x1000 - (iVar1 + 0x10U & 0xfff) >> 2);
    if (DAT_0800ae28 <= param_1) {
      param_1 = DAT_0800ae28;
    }
    iVar1 = (param_1 + 4) * 4;
  }
  iVar1 = FUN_08008466(iVar1);
  *(uint *)(iVar1 + 4) = param_1;
  *(undefined4 *)(iVar1 + 8) = 0;
  return;
}

