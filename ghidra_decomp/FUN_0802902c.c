
int FUN_0802902c(undefined4 param_1,int param_2,int param_3,uint param_4)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  uint *puVar5;
  
  iVar4 = *(int *)(param_2 + 0x10);
  iVar1 = 0;
  puVar5 = (uint *)(param_2 + 0x14);
  do {
    param_4 = param_3 * (*puVar5 & 0xffff) + param_4;
    uVar3 = param_3 * (*puVar5 >> 0x10) + (param_4 >> 0x10);
    iVar1 = iVar1 + 1;
    *puVar5 = (param_4 & 0xffff) + uVar3 * 0x10000;
    param_4 = uVar3 >> 0x10;
    puVar5 = puVar5 + 1;
  } while (iVar1 < iVar4);
  iVar1 = param_2;
  if (param_4 != 0) {
    if (*(int *)(param_2 + 8) <= iVar4) {
      iVar1 = FUN_08028f6c(param_1,*(int *)(param_2 + 4) + 1);
      iVar2 = iVar1;
      if (iVar1 == 0) {
        iVar2 = FUN_08028754(DAT_080290b4,0xba,0,DAT_080290b0);
      }
      FUN_08028666(iVar2 + 0xc,param_2 + 0xc,(*(int *)(param_2 + 0x10) + 2) * 4);
      FUN_08028fe8(param_1,param_2);
    }
    *(uint *)(iVar1 + iVar4 * 4 + 0x14) = param_4;
    *(int *)(iVar1 + 0x10) = iVar4 + 1;
  }
  return iVar1;
}

