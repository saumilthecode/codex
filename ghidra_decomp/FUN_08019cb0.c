
undefined4
FUN_08019cb0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5
            ,undefined4 param_6,int param_7)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined1 *puVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  int *piVar8;
  int *piVar9;
  int local_a0 [4];
  undefined1 auStack_90 [8];
  undefined1 auStack_88 [72];
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 uStack_34;
  int local_2c [2];
  
  local_40 = param_2;
  local_3c = param_1;
  local_38 = param_3;
  uStack_34 = param_4;
  iVar1 = FUN_08018fd4(param_5 + 0x6c);
  uVar5 = *(uint *)(param_5 + 0xc);
  uVar7 = uVar5 & 0x4a;
  piVar8 = local_a0;
  iVar3 = param_7;
  if (uVar7 == 0x40) {
LAB_08019db0:
    iVar6 = 0;
  }
  else if (param_7 < 1) {
    if (uVar7 == 8) goto LAB_08019db0;
    iVar6 = 1;
    iVar3 = -param_7;
  }
  else {
    iVar6 = uVar7 - 8;
    if (iVar6 != 0) {
      iVar6 = 1;
    }
  }
  local_a0[0] = iVar6;
  local_2c[0] = FUN_080191cc(&local_40,iVar3,iVar1 + 0x2c,uVar5);
  puVar4 = auStack_90 + (0x14 - local_2c[0]) * 4;
  if (*(char *)(iVar1 + 0x10) != '\0') {
    iVar3 = -(local_2c[0] * 8 + 8);
    piVar8 = (int *)((int)local_a0 + iVar3);
    puVar4 = auStack_88 + iVar3;
    *(undefined1 **)((int)local_a0 + iVar3 + 8) = auStack_90 + (0x14 - local_2c[0]) * 4;
    *(int **)((int)local_a0 + iVar3 + 0xc) = local_2c;
    *(int *)((int)local_a0 + iVar3) = param_5;
    *(undefined1 **)((int)local_a0 + iVar3 + 4) = puVar4;
    FUN_080191a2(local_40,*(undefined4 *)(iVar1 + 8),*(undefined4 *)(iVar1 + 0xc),
                 *(undefined4 *)(iVar1 + 0x28));
  }
  if (iVar6 == 0) {
    if ((-1 < (int)(uVar5 << 0x16)) || (param_7 == 0)) goto LAB_08019d58;
    if (uVar7 != 0x40) {
      *(undefined4 *)(puVar4 + -4) =
           *(undefined4 *)(iVar1 + 0x2c + (2 - ((int)(uVar5 << 0x11) >> 0x1f)) * 4);
      *(undefined4 *)(puVar4 + -8) = *(undefined4 *)(iVar1 + 0x3c);
      puVar4 = puVar4 + -8;
      local_2c[0] = local_2c[0] + 2;
      goto LAB_08019d58;
    }
    uVar2 = *(undefined4 *)(iVar1 + 0x3c);
  }
  else if (param_7 < 0) {
    uVar2 = *(undefined4 *)(iVar1 + 0x2c);
  }
  else {
    if (-1 < (int)(uVar5 << 0x14)) goto LAB_08019d58;
    uVar2 = *(undefined4 *)(iVar1 + 0x30);
  }
  *(undefined4 *)(puVar4 + -4) = uVar2;
  puVar4 = puVar4 + -4;
  local_2c[0] = local_2c[0] + 1;
LAB_08019d58:
  iVar3 = *(int *)(param_5 + 8);
  piVar9 = piVar8;
  if (local_2c[0] < iVar3) {
    iVar1 = -(iVar3 * 4 + 7U & 0xfffffff8);
    piVar9 = (int *)((int)piVar8 + iVar1);
    *(undefined1 **)((int)piVar8 + iVar1 + 4) = puVar4;
    *(int **)((int)piVar8 + iVar1 + 8) = local_2c;
    puVar4 = (undefined1 *)((int)piVar8 + iVar1 + 0x10);
    *(undefined1 **)((int)piVar8 + iVar1) = puVar4;
    FUN_08019c94(local_40,param_6,iVar3,param_5);
  }
  *(undefined4 *)(param_5 + 8) = 0;
  *piVar9 = local_2c[0];
  FUN_080195b4(local_3c,local_38,uStack_34,puVar4);
  return local_3c;
}

