
uint FUN_08001cc8(void)

{
  longlong lVar1;
  undefined4 in_r3;
  uint uVar2;
  
  uVar2 = *(uint *)(DAT_08001d24 + 8) & 0xc;
  if (uVar2 == 4) {
    return DAT_08001d2c;
  }
  if (uVar2 != 8) {
    return DAT_08001d28;
  }
  uVar2 = *(uint *)(DAT_08001d24 + 4) & 0x3f;
  if ((*(uint *)(DAT_08001d24 + 4) & 0x400000) == 0) {
    lVar1 = (ulonglong)((uint)(*(int *)(DAT_08001d24 + 4) << 0x11) >> 0x17) *
            (ulonglong)DAT_08001d28;
    uVar2 = FUN_08006980((int)lVar1,(int)((ulonglong)lVar1 >> 0x20),uVar2,0,in_r3);
  }
  else {
    lVar1 = (ulonglong)((uint)(*(int *)(DAT_08001d24 + 4) << 0x11) >> 0x17) *
            (ulonglong)DAT_08001d2c;
    uVar2 = FUN_08006980((int)lVar1,(int)((ulonglong)lVar1 >> 0x20),uVar2,0,in_r3);
  }
  return uVar2 / ((((uint)(*(int *)(DAT_08001d24 + 4) << 0xe) >> 0x1e) + 1) * 2);
}

