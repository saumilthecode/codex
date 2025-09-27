
undefined4 FUN_080035bc(int *param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  if ((param_1[0x12] == 0) || (iVar1 = FUN_08000d04(), iVar1 == 0)) {
    uVar2 = 0;
  }
  else {
    uVar2 = 1;
    param_1[0x15] = param_1[0x15] | 0x10;
  }
  if ((param_1[0x13] != 0) && (iVar1 = FUN_08000d04(), iVar1 != 0)) {
    uVar2 = 1;
    param_1[0x15] = param_1[0x15] | 0x10;
  }
  *(uint *)(*param_1 + 4) = *(uint *)(*param_1 + 4) & 0xfffffffc;
  *(undefined1 *)((int)param_1 + 0x51) = 1;
  return uVar2;
}

