
undefined4
FUN_08019f00(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5
            ,undefined4 param_6,int param_7)

{
  int iVar1;
  int iVar2;
  undefined1 *puVar3;
  uint uVar4;
  uint uVar5;
  uint *puVar6;
  int *piVar7;
  uint local_a0 [4];
  undefined1 auStack_90 [8];
  undefined1 auStack_88 [72];
  uint local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 uStack_34;
  int local_2c [2];
  
  local_3c = param_1;
  local_38 = param_3;
  uStack_34 = param_4;
  iVar2 = FUN_08018fd4(param_5 + 0x6c);
  uVar4 = *(uint *)(param_5 + 0xc);
  uVar5 = uVar4 & 0x4a;
  puVar6 = local_a0;
  local_a0[0] = (uint)(uVar5 != 0x40 && uVar5 != 8);
  local_40 = local_a0[0];
  local_2c[0] = FUN_080191cc(&local_40,param_7,iVar2 + 0x2c,uVar4);
  puVar3 = auStack_90 + (0x14 - local_2c[0]) * 4;
  if (*(char *)(iVar2 + 0x10) != '\0') {
    iVar1 = -(local_2c[0] * 8 + 8);
    puVar6 = (uint *)((int)local_a0 + iVar1);
    puVar3 = auStack_88 + iVar1;
    *(undefined1 **)((int)local_a0 + iVar1 + 8) = auStack_90 + (0x14 - local_2c[0]) * 4;
    *(int **)((int)local_a0 + iVar1 + 0xc) = local_2c;
    *(int *)((int)local_a0 + iVar1) = param_5;
    *(undefined1 **)((int)local_a0 + iVar1 + 4) = puVar3;
    FUN_080191a2(param_2,*(undefined4 *)(iVar2 + 8),*(undefined4 *)(iVar2 + 0xc),
                 *(undefined4 *)(iVar2 + 0x28));
  }
  if (((local_40 == 0) && ((int)(uVar4 << 0x16) < 0)) && (param_7 != 0)) {
    if (uVar5 == 0x40) {
      *(undefined4 *)(puVar3 + -4) = *(undefined4 *)(iVar2 + 0x3c);
      puVar3 = puVar3 + -4;
      local_2c[0] = local_2c[0] + 1;
    }
    else {
      *(undefined4 *)(puVar3 + -4) =
           *(undefined4 *)(iVar2 + 0x2c + (2 - ((int)(uVar4 << 0x11) >> 0x1f)) * 4);
      *(undefined4 *)(puVar3 + -8) = *(undefined4 *)(iVar2 + 0x3c);
      puVar3 = puVar3 + -8;
      local_2c[0] = local_2c[0] + 2;
    }
  }
  iVar2 = *(int *)(param_5 + 8);
  piVar7 = (int *)puVar6;
  if (local_2c[0] < iVar2) {
    iVar1 = -(iVar2 * 4 + 7U & 0xfffffff8);
    piVar7 = (int *)((int)puVar6 + iVar1);
    *(undefined1 **)((int)puVar6 + iVar1 + 4) = puVar3;
    *(int **)((int)puVar6 + iVar1 + 8) = local_2c;
    puVar3 = (undefined1 *)((int)puVar6 + iVar1 + 0x10);
    *(undefined1 **)((int)puVar6 + iVar1) = puVar3;
    FUN_08019c94(param_2,param_6,iVar2,param_5);
  }
  *(undefined4 *)(param_5 + 8) = 0;
  *piVar7 = local_2c[0];
  FUN_080195b4(local_3c,local_38,uStack_34,puVar3);
  return local_3c;
}

