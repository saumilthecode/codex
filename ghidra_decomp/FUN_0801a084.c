
undefined4
FUN_0801a084(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5
            ,undefined4 param_6,int param_7,int param_8)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  undefined1 *puVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  int *piVar9;
  int *piVar10;
  int local_f8 [4];
  undefined1 auStack_e8 [8];
  undefined1 auStack_e0 [152];
  undefined1 auStack_48 [4];
  int local_44;
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
  local_44 = iVar1 + 0x2c;
  uVar6 = *(uint *)(param_5 + 0xc);
  uVar8 = uVar6 & 0x4a;
  piVar9 = local_f8;
  iVar3 = param_7;
  iVar4 = param_8;
  if (uVar8 == 0x40) {
LAB_0801a1a0:
    iVar7 = 0;
  }
  else if (param_8 < (int)(uint)(param_7 == 0)) {
    if (uVar8 == 8) goto LAB_0801a1a0;
    iVar7 = 1;
    iVar3 = -param_7;
    iVar4 = -param_8 - (uint)(param_7 != 0);
  }
  else {
    iVar7 = uVar8 - 8;
    if (iVar7 != 0) {
      iVar7 = 1;
    }
  }
  local_f8[0] = iVar1 + 0x2c;
  local_f8[1] = uVar6;
  local_f8[2] = iVar7;
  local_2c[0] = FUN_08019236(auStack_48,local_f8[0],iVar3,iVar4);
  puVar5 = auStack_e8 + (0x28 - local_2c[0]) * 4;
  if (*(char *)(iVar1 + 0x10) != '\0') {
    iVar3 = -(local_2c[0] * 8 + 8);
    piVar9 = (int *)((int)local_f8 + iVar3);
    *(undefined1 **)((int)local_f8 + iVar3 + 8) = puVar5;
    *(int **)((int)local_f8 + iVar3 + 0xc) = local_2c;
    puVar5 = auStack_e0 + iVar3;
    *(undefined1 **)((int)local_f8 + iVar3 + 4) = puVar5;
    *(int *)((int)local_f8 + iVar3) = param_5;
    FUN_080191a2(local_40,*(undefined4 *)(iVar1 + 8),*(undefined4 *)(iVar1 + 0xc),
                 *(undefined4 *)(iVar1 + 0x28));
  }
  if (iVar7 == 0) {
    if ((-1 < (int)(uVar6 << 0x16)) || (param_7 == 0 && param_8 == 0)) goto LAB_0801a140;
    if (uVar8 != 0x40) {
      *(undefined4 *)(puVar5 + -4) =
           *(undefined4 *)(iVar1 + 0x2c + (2 - ((int)(uVar6 << 0x11) >> 0x1f)) * 4);
      *(undefined4 *)(puVar5 + -8) = *(undefined4 *)(iVar1 + 0x3c);
      puVar5 = puVar5 + -8;
      local_2c[0] = local_2c[0] + 2;
      goto LAB_0801a140;
    }
    uVar2 = *(undefined4 *)(iVar1 + 0x3c);
  }
  else if (param_8 < 0) {
    uVar2 = *(undefined4 *)(iVar1 + 0x2c);
  }
  else {
    if (-1 < (int)(uVar6 << 0x14)) goto LAB_0801a140;
    uVar2 = *(undefined4 *)(iVar1 + 0x30);
  }
  *(undefined4 *)(puVar5 + -4) = uVar2;
  puVar5 = puVar5 + -4;
  local_2c[0] = local_2c[0] + 1;
LAB_0801a140:
  iVar3 = *(int *)(param_5 + 8);
  piVar10 = piVar9;
  if (local_2c[0] < iVar3) {
    iVar4 = -(iVar3 * 4 + 7U & 0xfffffff8);
    piVar10 = (int *)((int)piVar9 + iVar4);
    *(undefined1 **)((int)piVar9 + iVar4 + 4) = puVar5;
    *(int **)((int)piVar9 + iVar4 + 8) = local_2c;
    puVar5 = (undefined1 *)((int)piVar9 + iVar4 + 0x10);
    *(undefined1 **)((int)piVar9 + iVar4) = puVar5;
    FUN_08019c94(local_40,param_6,iVar3,param_5);
  }
  *(undefined4 *)(param_5 + 8) = 0;
  *piVar10 = local_2c[0];
  FUN_080195b4(local_3c,local_38,uStack_34,puVar5);
  return local_3c;
}

