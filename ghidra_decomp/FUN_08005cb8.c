
undefined4 FUN_08005cb8(int *param_1,int param_2,undefined2 param_3)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *param_1;
  param_1[0x11] = 0;
  *(undefined1 *)((int)param_1 + 0x42) = 0x22;
  iVar2 = param_1[0xf];
  param_1[10] = param_2;
  *(undefined2 *)(param_1 + 0xb) = param_3;
  *(undefined4 *)(iVar2 + 0x50) = 0;
  *(undefined4 *)(iVar2 + 0x3c) = DAT_08005d58;
  *(undefined4 *)(iVar2 + 0x40) = DAT_08005d5c;
  *(undefined4 *)(iVar2 + 0x4c) = DAT_08005d60;
  iVar2 = FUN_08000c8c(iVar2,iVar3 + 4,param_2);
  if (iVar2 != 0) {
    param_1[0x11] = 0x10;
    *(undefined1 *)((int)param_1 + 0x42) = 0x20;
    return 1;
  }
  iVar2 = *param_1;
  if (param_1[4] != 0) {
    do {
      ExclusiveAccess((uint *)(iVar2 + 0xc));
      bVar1 = (bool)hasExclusiveAccess((uint *)(iVar2 + 0xc));
    } while (!bVar1);
    *(uint *)(iVar2 + 0xc) = *(uint *)(iVar2 + 0xc) | 0x100;
  }
  do {
    ExclusiveAccess((uint *)(iVar2 + 0x14));
    bVar1 = (bool)hasExclusiveAccess((uint *)(iVar2 + 0x14));
  } while (!bVar1);
  *(uint *)(iVar2 + 0x14) = *(uint *)(iVar2 + 0x14) | 1;
  do {
    ExclusiveAccess((uint *)(iVar2 + 0x14));
    bVar1 = (bool)hasExclusiveAccess((uint *)(iVar2 + 0x14));
  } while (!bVar1);
  *(uint *)(iVar2 + 0x14) = *(uint *)(iVar2 + 0x14) | 0x40;
  return 0;
}

