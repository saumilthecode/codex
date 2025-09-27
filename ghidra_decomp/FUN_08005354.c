
undefined4 FUN_08005354(int *param_1)

{
  bool bVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  
  iVar5 = *param_1;
  do {
    ExclusiveAccess((uint *)(iVar5 + 0xc));
    bVar1 = (bool)hasExclusiveAccess((uint *)(iVar5 + 0xc));
  } while (!bVar1);
  *(uint *)(iVar5 + 0xc) = *(uint *)(iVar5 + 0xc) & 0xfffffe1f;
  do {
    ExclusiveAccess((uint *)(iVar5 + 0x14));
    bVar1 = (bool)hasExclusiveAccess((uint *)(iVar5 + 0x14));
    bVar1 = !bVar1;
  } while (bVar1);
  *(uint *)(iVar5 + 0x14) = *(uint *)(iVar5 + 0x14) & 0xfffffffe;
  if (param_1[0xc] == 1) {
    do {
      ExclusiveAccess((uint *)(iVar5 + 0xc));
      bVar2 = (bool)hasExclusiveAccess((uint *)(iVar5 + 0xc));
    } while (!bVar2);
    *(uint *)(iVar5 + 0xc) = *(uint *)(iVar5 + 0xc) & 0xffffffef;
  }
  iVar6 = param_1[0xe];
  if (iVar6 != 0) {
    uVar4 = *(uint *)(iVar5 + 0x14) & 0x80;
    if (uVar4 != 0) {
      uVar4 = DAT_08005468;
    }
    *(uint *)(iVar6 + 0x50) = uVar4;
  }
  iVar3 = param_1[0xf];
  if (iVar3 != 0) {
    uVar4 = *(uint *)(iVar5 + 0x14) & 0x40;
    if (uVar4 != 0) {
      uVar4 = DAT_0800546c;
    }
    *(uint *)(iVar3 + 0x50) = uVar4;
  }
  if (*(int *)(iVar5 + 0x14) << 0x18 < 0) {
    do {
      ExclusiveAccess((uint *)(iVar5 + 0x14));
      bVar2 = (bool)hasExclusiveAccess((uint *)(iVar5 + 0x14));
    } while (!bVar2);
    *(uint *)(iVar5 + 0x14) = *(uint *)(iVar5 + 0x14) & 0xffffff7f;
    if (iVar6 == 0) goto LAB_080053b6;
    iVar6 = FUN_08000d98(iVar6);
    iVar5 = *param_1;
    if (iVar6 == 0) {
      if (-1 < *(int *)(iVar5 + 0x14) << 0x19) {
        return 0;
      }
      iVar3 = param_1[0xf];
    }
    else {
      iVar6 = *(int *)(iVar5 + 0x14);
      *(undefined4 *)(param_1[0xe] + 0x50) = 0;
      if (-1 < iVar6 << 0x19) goto LAB_080053e6;
      iVar3 = param_1[0xf];
      bVar1 = true;
    }
  }
  else {
LAB_080053b6:
    if (-1 < *(int *)(iVar5 + 0x14) << 0x19) goto LAB_080053e6;
    bVar1 = true;
  }
  do {
    ExclusiveAccess((uint *)(iVar5 + 0x14));
    bVar2 = (bool)hasExclusiveAccess((uint *)(iVar5 + 0x14));
  } while (!bVar2);
  *(uint *)(iVar5 + 0x14) = *(uint *)(iVar5 + 0x14) & 0xffffffbf;
  if (iVar3 == 0) {
    if (!bVar1) {
      return 0;
    }
  }
  else {
    iVar5 = FUN_08000d98();
    if (iVar5 == 0) {
      return 0;
    }
    *(undefined4 *)(param_1[0xf] + 0x50) = 0;
  }
LAB_080053e6:
  *(undefined2 *)((int)param_1 + 0x26) = 0;
  *(undefined2 *)((int)param_1 + 0x2e) = 0;
  param_1[0x11] = 0;
  *(undefined1 *)((int)param_1 + 0x41) = 0x20;
  *(undefined1 *)((int)param_1 + 0x42) = 0x20;
  param_1[0xc] = 0;
  FUN_08005350(param_1);
  return 0;
}

