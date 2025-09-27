
uint FUN_080259b4(uint param_1,undefined4 param_2)

{
  int iVar1;
  uint uVar2;
  
  switch(param_2) {
  case 1:
    if (param_1 < 0x100) {
      uVar2 = *(byte *)(DAT_08029b58 + param_1) & 7;
    }
    else {
      uVar2 = 0;
    }
    return uVar2;
  case 2:
    if (param_1 < 0x100) {
      uVar2 = *(byte *)(DAT_08029b74 + param_1) & 3;
    }
    else {
      uVar2 = 0;
    }
    return uVar2;
  case 3:
    break;
  case 4:
    if (param_1 < 0x100) {
      uVar2 = *(byte *)(DAT_08029bbc + param_1) & 0x20;
    }
    else {
      uVar2 = 0;
    }
    return uVar2;
  case 5:
    return (uint)(param_1 - 0x30 < 10);
  case 6:
    uVar2 = FUN_08025a58();
    if (uVar2 != 0) {
      iVar1 = FUN_08025a90(param_1,0);
      uVar2 = (uint)(iVar1 == 0);
    }
    return uVar2;
  case 7:
    if (0xff < param_1) {
      return 0;
    }
    return (uint)((*(byte *)(DAT_08025a4c + param_1) & 3) == 2);
  case 8:
    uVar2 = FUN_08025a58(param_1,0);
    return uVar2;
  case 9:
    if (param_1 < 0x100) {
      uVar2 = *(byte *)(DAT_08025a84 + param_1) & 0x10;
    }
    else {
      uVar2 = 0;
    }
    return uVar2;
  case 10:
    uVar2 = FUN_08025a90(param_1,0);
    return uVar2;
  case 0xb:
    if (0xff < param_1) {
      return 0;
    }
    return (uint)((*(byte *)(DAT_08025ac4 + param_1) & 3) == 1);
  case 0xc:
    if (param_1 - 0x30 < 10) {
      return 1;
    }
    return (uint)((param_1 & 0xffffffdf) - 0x41 < 6);
  default:
    return 0;
  }
  if (0xff < param_1) {
    return 0;
  }
  if (*(char *)(DAT_08029ba0 + param_1) < '\0') {
    return 1;
  }
  return (uint)(param_1 == 9);
}

