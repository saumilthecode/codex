
undefined4 *
FUN_0800e538(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,uint *param_7,int param_8,int param_9,int param_10
            ,uint *param_11)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  uint uVar4;
  uint *puVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint *puVar11;
  uint local_38 [5];
  
  local_38[2] = param_3;
  local_38[3] = param_4;
  local_38[1] = FUN_08018e8c(param_10 + 0x6c);
  puVar5 = local_38 + param_9 * -2;
  iVar1 = FUN_0800e0fc(local_38 + 2,&param_5);
  if (iVar1 == 0) {
    uVar2 = 0;
    uVar9 = 0;
    puVar11 = (uint *)0x0;
  }
  else {
    uVar2 = FUN_0800e0b8(local_38 + 2);
    uVar4 = local_38[3];
    uVar8 = local_38[2];
    uVar10 = param_9 * 2;
    uVar7 = 0;
    for (uVar9 = 0; uVar9 < uVar10; uVar9 = uVar9 + 1) {
      if ((**(uint **)(param_8 + uVar9 * 4) == uVar2) ||
         (local_38[0] = uVar2, uVar6 = FUN_0800e0ac(local_38[1]), uVar2 = local_38[0],
         uVar6 == local_38[0])) {
        puVar5[uVar7] = uVar9;
        uVar7 = uVar7 + 1;
      }
    }
    if (uVar7 == 0) {
      uVar2 = 0;
      uVar9 = 0;
      puVar11 = (uint *)0x0;
      local_38[2] = uVar8;
      local_38[3] = uVar4;
    }
    else {
      FUN_0800d316(uVar8);
      iVar1 = -(uVar7 * 4 + 7 & 0xfffffff8);
      puVar11 = (uint *)((int)puVar5 + iVar1);
      uVar9 = 0;
      do {
        uVar3 = FUN_0802698c(*(undefined4 *)(param_8 + puVar5[uVar9] * 4));
        *(undefined4 *)((int)puVar5 + uVar9 * 4 + iVar1) = uVar3;
        uVar9 = uVar9 + 1;
      } while (uVar7 != uVar9);
      uVar2 = 1;
      local_38[2] = uVar8;
      local_38[3] = 0xffffffff;
    }
  }
  while (iVar1 = FUN_0800e0fc(local_38 + 2,&param_5), uVar4 = local_38[3], uVar8 = local_38[2],
        iVar1 != 0) {
    local_38[1] = FUN_0800e0b8(local_38 + 2);
    uVar4 = local_38[3];
    uVar8 = local_38[2];
    uVar6 = 0;
    uVar10 = 0;
    uVar7 = uVar9;
    while (uVar6 < uVar7) {
      local_38[0] = uVar6 << 2;
      if (uVar2 < puVar11[uVar6]) {
        if (*(int *)(*(int *)(param_8 + puVar5[uVar6] * 4) + uVar2 * 4) == local_38[1])
        goto LAB_0800e670;
        uVar7 = uVar7 - 1;
        puVar5[uVar6] = puVar5[uVar7];
        puVar11[uVar6] = puVar11[uVar7];
      }
      else {
        uVar10 = uVar10 + 1;
LAB_0800e670:
        uVar6 = uVar6 + 1;
      }
    }
    uVar9 = uVar10;
    if (uVar7 == uVar10) break;
    FUN_0800d316(uVar8);
    uVar2 = uVar2 + 1;
    local_38[2] = uVar8;
    uVar9 = uVar7;
    local_38[3] = 0xffffffff;
  }
  if (uVar9 == 1) {
    uVar9 = *puVar11;
LAB_0800e5ea:
    if (uVar9 != uVar2) {
LAB_0800e6ca:
      uVar2 = *param_11 | 4;
      goto LAB_0800e5fa;
    }
  }
  else {
    if (uVar9 != 2) goto LAB_0800e6ca;
    if (*puVar11 != uVar2) {
      uVar9 = puVar11[1];
      goto LAB_0800e5ea;
    }
  }
  uVar2 = *puVar5;
  param_11 = param_7;
  if (param_9 <= (int)uVar2) {
    uVar2 = uVar2 - param_9;
  }
LAB_0800e5fa:
  *param_11 = uVar2;
  *param_1 = uVar8;
  param_1[1] = uVar4;
  return param_1;
}

