
undefined4 *
FUN_0800d854(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            int param_5,undefined4 param_6,undefined4 *param_7)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  uint uVar6;
  uint uVar7;
  int *piVar8;
  int *piVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  bool bVar13;
  undefined4 *local_7c;
  undefined4 local_6c;
  undefined4 local_64;
  undefined4 local_60;
  char local_5c;
  undefined3 uStack_5b;
  undefined4 *local_58;
  uint local_54;
  undefined4 auStack_50 [4];
  undefined4 *local_40;
  uint local_3c;
  undefined4 auStack_38 [5];
  
  piVar1 = (int *)FUN_08018e8c(param_5 + 0x6c);
  iVar2 = FUN_0800d608(param_5 + 0x6c);
  piVar9 = (int *)*param_7;
  uVar7 = param_7[1];
  iVar3 = iVar2;
  if (*piVar9 == *(int *)(iVar2 + 0x40)) goto LAB_0800d91c;
  local_64 = *(undefined4 *)(iVar2 + 0x38);
  uVar11 = *(uint *)(iVar2 + 0x28);
  local_7c = *(undefined4 **)(iVar2 + 0x24);
  while( true ) {
    iVar3 = (**(code **)(*piVar1 + 0x14))(piVar1,4,piVar9,piVar9 + uVar7);
    piVar8 = (int *)(iVar3 - (int)piVar9 >> 2);
    local_6c = param_4;
    if (piVar8 == (int *)0x0) break;
    local_58 = auStack_50;
    local_54 = 0;
    auStack_50[0] = 0;
    FUN_0801eb48(&local_58,(int)piVar8 << 1);
    piVar1 = (int *)((int)piVar8 - *(int *)(iVar2 + 0x34));
    if ((int)piVar1 < 1) {
LAB_0800d93a:
      if (0 < *(int *)(iVar2 + 0x34)) {
        FUN_0801eb7e(&local_58,*(undefined4 *)(iVar2 + 0x14));
        if ((int)piVar1 < 0) {
          FUN_0800d460(&local_58,-(int)piVar1,*(undefined4 *)(iVar2 + 0x44));
        }
        else {
          piVar8 = *(int **)(iVar2 + 0x34);
          piVar9 = piVar9 + (int)piVar1;
        }
        FUN_0800d474(&local_58,piVar9,piVar8);
      }
      uVar12 = *(uint *)(param_5 + 0xc) & 0xb0;
      uVar7 = *(uint *)(param_5 + 0xc) & 0x200;
      if (uVar7 != 0) {
        uVar7 = *(uint *)(iVar2 + 0x20);
      }
      uVar7 = uVar7 + local_54 + uVar11;
      iVar3 = 0;
      local_40 = auStack_38;
      local_3c = 0;
      auStack_38[0] = 0;
      FUN_0801eb48(&local_40,uVar7 * 2);
      uVar10 = *(uint *)(param_5 + 8);
      bVar13 = uVar7 < uVar10;
      if (uVar12 != 0x10) {
        bVar13 = false;
      }
      goto LAB_0800d99c;
    }
    if (*(int *)(iVar2 + 0x34) < 0) {
      piVar1 = piVar8;
    }
    if (*(int *)(iVar2 + 0xc) == 0) {
      FUN_0801ecfc(&local_58,0,local_54,piVar9,piVar1);
      goto LAB_0800d93a;
    }
    FUN_0801ebb4(&local_58,0,local_54,(int)piVar1 << 1,0);
    puVar4 = local_58;
    iVar3 = FUN_080190b6(local_58,*(undefined4 *)(iVar2 + 0x18),*(undefined4 *)(iVar2 + 8),
                         *(undefined4 *)(iVar2 + 0xc),piVar9,piVar9 + (int)piVar1);
    uVar7 = iVar3 - (int)puVar4 >> 2;
    if (uVar7 <= local_54) {
      *(undefined4 *)((int)local_58 + (iVar3 - (int)puVar4)) = 0;
      local_54 = uVar7;
      goto LAB_0800d93a;
    }
    uVar7 = local_54;
    iVar3 = FUN_08010508(DAT_0800daa8,DAT_0800daa4);
LAB_0800d91c:
    local_64 = *(undefined4 *)(iVar3 + 0x3c);
    local_7c = *(undefined4 **)(iVar3 + 0x2c);
    uVar11 = *(uint *)(iVar3 + 0x30);
    if (uVar7 != 0) {
      piVar9 = piVar9 + 1;
    }
  }
  goto LAB_0800da46;
LAB_0800d99c:
  do {
    switch(*(undefined1 *)((int)&local_64 + iVar3)) {
    case 0:
      if (bVar13) {
LAB_0800da7c:
        FUN_0800d460(&local_40,uVar10 - uVar7,param_6);
      }
      break;
    case 1:
      uVar5 = param_6;
      if (bVar13) goto LAB_0800da7c;
LAB_0800da68:
      FUN_0801eb7e(&local_40,uVar5);
      break;
    case 2:
      if (*(int *)(param_5 + 0xc) << 0x16 < 0) {
        puVar4 = *(undefined4 **)(iVar2 + 0x1c);
        uVar6 = *(uint *)(iVar2 + 0x20);
        goto LAB_0800d9d8;
      }
      break;
    case 3:
      if (uVar11 != 0) {
        uVar5 = *local_7c;
        goto LAB_0800da68;
      }
      break;
    case 4:
      puVar4 = local_58;
      uVar6 = local_54;
LAB_0800d9d8:
      FUN_0800d474(&local_40,puVar4,uVar6);
    }
    iVar3 = iVar3 + 1;
  } while (iVar3 != 4);
  if (1 < uVar11) {
    FUN_0800d474(&local_40,local_7c + 1,uVar11 - 1);
  }
  uVar7 = local_3c;
  if (local_3c < uVar10) {
    uVar7 = uVar10;
    if (uVar12 == 0x20) {
      FUN_0800d460(&local_40,uVar10 - local_3c);
    }
    else {
      FUN_0801ebb4(&local_40,0,0,uVar10 - local_3c,param_6);
    }
  }
  local_6c._0_1_ = (char)param_4;
  if (((char)local_6c == '\0') && (uVar11 = FUN_08017cb8(param_3,local_40,uVar7), uVar7 != uVar11))
  {
    local_6c._0_1_ = '\x01';
  }
  _local_5c = CONCAT31(uStack_5b,(char)local_6c);
  local_6c._1_3_ = (undefined3)((uint)param_4 >> 8);
  local_60 = param_3;
  FUN_0801e9cc(&local_40);
  FUN_0801e9cc(&local_58);
LAB_0800da46:
  *(undefined4 *)(param_5 + 8) = 0;
  *param_1 = param_3;
  param_1[1] = local_6c;
  return param_1;
}

