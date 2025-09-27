
undefined4
FUN_080123b0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5
            ,undefined1 param_6,undefined1 param_7,undefined4 param_8,int param_9,
            undefined4 param_10)

{
  undefined1 uVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  undefined1 *puVar5;
  char *pcVar6;
  int iVar7;
  undefined1 *puVar8;
  uint uVar9;
  undefined1 *puVar10;
  int iVar11;
  undefined1 *puVar12;
  int *piVar13;
  int local_90 [3];
  undefined4 uStack_84;
  char acStack_80 [48];
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 uStack_44;
  int local_40;
  undefined4 local_3c;
  undefined1 auStack_38 [20];
  
  local_50 = param_2;
  local_4c = param_1;
  local_48 = param_3;
  uStack_44 = param_4;
  iVar3 = FUN_0801139c(param_5 + 0x6c);
  iVar7 = *(int *)(param_5 + 4);
  if (iVar7 < 0) {
    iVar7 = 6;
  }
  FUN_0801faf0(param_5,auStack_38,param_7);
  uVar9 = *(uint *)(param_5 + 0xc) & 0x104;
  pcVar6 = acStack_80;
  if (uVar9 == 0x104) {
    local_3c = FUN_08008940();
    local_90[0] = param_9;
    local_90[1] = param_10;
    local_40 = FUN_0800d708(&local_3c,pcVar6,0x2d,auStack_38);
  }
  else {
    local_3c = FUN_08008940();
    local_90[2] = param_9;
    uStack_84 = param_10;
    local_90[0] = iVar7;
    local_40 = FUN_0800d708(&local_3c,pcVar6,0x2d,auStack_38);
  }
  piVar13 = local_90;
  if (0x2c < local_40) {
    iVar11 = local_40 + 1;
    iVar2 = -(local_40 + 8U & 0xfffffff8);
    piVar13 = (int *)((int)local_90 + iVar2);
    pcVar6 = acStack_80 + iVar2;
    if (uVar9 == 0x104) {
      local_3c = FUN_08008940();
      *(int *)((int)local_90 + iVar2) = param_9;
      *(undefined4 *)((int)local_90 + iVar2 + 4) = param_10;
      local_40 = FUN_0800d708(&local_3c,pcVar6,iVar11,auStack_38);
    }
    else {
      local_3c = FUN_08008940();
      *(int *)((int)local_90 + iVar2 + 8) = param_9;
      *(undefined4 *)(acStack_80 + iVar2 + -4) = param_10;
      *(int *)((int)local_90 + iVar2) = iVar7;
      local_40 = FUN_0800d708(&local_3c,pcVar6,iVar11,auStack_38);
      piVar13 = (int *)((int)local_90 + iVar2);
    }
  }
  uVar4 = FUN_0801126c(param_5 + 0x6c);
  iVar2 = -(local_40 + 7U & 0xfffffff8);
  puVar8 = (undefined1 *)((int)piVar13 + iVar2 + 0x10);
  FUN_08010c84(uVar4,pcVar6,pcVar6 + local_40,puVar8);
  iVar7 = local_40;
  puVar5 = (undefined1 *)FUN_08010cc6(pcVar6,local_40,0x2e);
  if (puVar5 != (undefined1 *)0x0) {
    *(undefined1 *)((int)piVar13 + ((int)puVar5 - (int)pcVar6) + iVar2 + 0x10) =
         *(undefined1 *)(iVar3 + 0x24);
    puVar5 = puVar8 + ((int)puVar5 - (int)pcVar6);
  }
  puVar10 = puVar8;
  puVar12 = (undefined1 *)((int)piVar13 + iVar2);
  if ((*(char *)(iVar3 + 0x10) != '\0') &&
     (((puVar5 != (undefined1 *)0x0 || (iVar7 < 3)) ||
      ((puVar12 = (undefined1 *)((int)piVar13 + iVar2), (byte)pcVar6[1] < 0x3a &&
       ((puVar12 = (undefined1 *)((int)piVar13 + iVar2), (byte)pcVar6[2] - 0x30 < 10 &&
        (puVar12 = (undefined1 *)((int)piVar13 + iVar2), 0x2f < (byte)pcVar6[1])))))))) {
    iVar11 = -(iVar7 * 2 + 7U & 0xfffffff8);
    puVar12 = (undefined1 *)((int)piVar13 + iVar11 + iVar2);
    puVar10 = (undefined1 *)((int)piVar13 + iVar11 + iVar2 + 0x10);
    if ((*pcVar6 == '-') || (*pcVar6 == '+')) {
      *puVar10 = *puVar8;
      local_40 = iVar7 + -1;
      iVar7 = 1;
    }
    else {
      iVar7 = 0;
    }
    uVar1 = *(undefined1 *)(iVar3 + 0x25);
    *(int **)((int)piVar13 + iVar11 + iVar2 + 0xc) = &local_40;
    *(undefined1 **)((int)piVar13 + iVar11 + iVar2 + 8) = puVar8 + iVar7;
    *(undefined1 **)((int)piVar13 + iVar11 + iVar2) = puVar5;
    *(undefined1 **)((int)piVar13 + iVar11 + iVar2 + 4) = puVar10 + iVar7;
    FUN_08011512(local_50,*(undefined4 *)(iVar3 + 8),*(undefined4 *)(iVar3 + 0xc),uVar1);
    iVar7 = iVar7 + local_40;
    local_40 = iVar7;
  }
  iVar3 = *(int *)(param_5 + 8);
  piVar13 = (int *)puVar12;
  if (iVar7 < iVar3) {
    iVar7 = -(iVar3 + 7U & 0xfffffff8);
    piVar13 = (int *)(puVar12 + iVar7);
    *(undefined1 **)(puVar12 + iVar7 + 4) = puVar10;
    *(int **)(puVar12 + iVar7 + 8) = &local_40;
    puVar10 = puVar12 + iVar7 + 0x10;
    *(undefined1 **)(puVar12 + iVar7) = puVar10;
    FUN_0801164e(local_50,param_6,iVar3,param_5);
  }
  *(undefined4 *)(param_5 + 8) = 0;
  *piVar13 = local_40;
  FUN_08011c98(local_4c,local_48,uStack_44,puVar10);
  return local_4c;
}

