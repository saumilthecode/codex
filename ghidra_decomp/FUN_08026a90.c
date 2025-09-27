
uint FUN_08026a90(int param_1)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = *(uint *)(param_1 + 0x14);
  iVar2 = 0x76c;
  if (-1 < (int)uVar1) {
    iVar2 = -100;
  }
  iVar2 = iVar2 + uVar1;
  if (((uVar1 & 3) == 0) && (iVar2 != (iVar2 / 100) * 100)) {
    uVar1 = 1;
  }
  else {
    uVar1 = (uint)(iVar2 % 400 == 0);
  }
  uVar1 = *(int *)(param_1 + 0x18) * 2 + *(int *)(param_1 + 0x1c) * 0x10 + uVar1;
  if (uVar1 == 0x16a2) {
    return 1;
  }
  if ((int)uVar1 < 0x16a3) {
    if ((int)uVar1 < 2) {
      return (int)~uVar1 >> 0x1f;
    }
    if (uVar1 - 10 < 0x18) {
      return (int)((DAT_08026b2c >> (uVar1 - 10 & 0xff)) << 0x1f) >> 0x1f;
    }
  }
  else {
    if ((int)uVar1 < 0x16b5) {
      return (uint)(0x16b1 < (int)uVar1);
    }
    if (uVar1 - 0x16c2 < 0x16) {
      return DAT_08026b30 >> (uVar1 - 0x16c2 & 0xff) & 1;
    }
  }
  return 0;
}

