
/* WARNING: Type propagation algorithm not settling */

undefined4 FUN_08001d30(int *param_1,uint param_2)

{
  uint *puVar1;
  int *piVar2;
  int iVar3;
  undefined4 uVar4;
  uint uVar5;
  int iVar6;
  
  puVar1 = DAT_08001e58;
  if (param_1 == (int *)0x0) {
    return 1;
  }
  if ((param_2 <= (*DAT_08001e58 & 7)) ||
     (*(char *)DAT_08001e58 = (char)param_2, (*puVar1 & 7) == param_2)) {
    iVar6 = *param_1;
    if (iVar6 << 0x1e < 0) {
      if (iVar6 << 0x1d < 0) {
        DAT_08001e5c[2] = DAT_08001e5c[2] | 0x1c00;
      }
      if (iVar6 << 0x1c < 0) {
        DAT_08001e5c[2] = DAT_08001e5c[2] | 0xe000;
      }
      DAT_08001e5c[2] = DAT_08001e5c[2] & 0xffffff0fU | param_1[2];
    }
    piVar2 = DAT_08001e5c;
    if (iVar6 << 0x1f < 0) {
      uVar5 = param_1[1];
      if (uVar5 == 1) {
        iVar6 = *DAT_08001e5c << 0xe;
      }
      else if (uVar5 - 2 < 2) {
        iVar6 = *DAT_08001e5c << 6;
      }
      else {
        iVar6 = *DAT_08001e5c << 0x1e;
      }
      if (-1 < iVar6) {
        return 1;
      }
      DAT_08001e5c[2] = DAT_08001e5c[2] & 0xfffffffcU | uVar5;
      iVar6 = FUN_0800061c();
      while ((piVar2[2] & 0xcU) != param_1[1] * 4) {
        iVar3 = FUN_0800061c();
        if (5000 < (uint)(iVar3 - iVar6)) {
          return 3;
        }
      }
    }
    puVar1 = DAT_08001e58;
    if (((*DAT_08001e58 & 7) <= param_2) ||
       (*(char *)DAT_08001e58 = (char)param_2, (*puVar1 & 7) == param_2)) {
      iVar6 = *param_1;
      if (iVar6 << 0x1d < 0) {
        DAT_08001e5c[2] = DAT_08001e5c[2] & 0xffffe3ffU | param_1[3];
      }
      if (iVar6 << 0x1c < 0) {
        DAT_08001e5c[2] = DAT_08001e5c[2] & 0xffff1fffU | param_1[4] << 3;
      }
      uVar5 = FUN_08001cc8();
      uVar4 = *DAT_08001e68;
      *DAT_08001e64 =
           uVar5 >> (uint)*(byte *)(DAT_08001e60 + ((uint)(DAT_08001e5c[2] << 0x18) >> 0x1c));
      FUN_0800058c(uVar4);
      return 0;
    }
  }
  return 1;
}

