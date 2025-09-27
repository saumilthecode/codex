
undefined4
FUN_08011f3e(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5
            ,undefined1 param_6,int param_7)

{
  undefined1 uVar1;
  int iVar2;
  int iVar3;
  undefined1 *puVar4;
  uint uVar5;
  uint uVar6;
  uint *puVar7;
  int *piVar8;
  uint local_68 [4];
  undefined1 auStack_56 [18];
  undefined1 auStack_44 [4];
  uint local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 uStack_34;
  int local_2c [2];
  
  local_3c = param_1;
  local_38 = param_3;
  uStack_34 = param_4;
  iVar3 = FUN_0801139c(param_5 + 0x6c);
  uVar5 = *(uint *)(param_5 + 0xc);
  uVar6 = uVar5 & 0x4a;
  puVar7 = local_68;
  local_68[0] = (uint)(uVar6 != 0x40 && uVar6 != 8);
  local_40 = local_68[0];
  local_2c[0] = FUN_0801166a(auStack_44,param_7,iVar3 + 0x26,uVar5);
  puVar4 = auStack_44 + -local_2c[0];
  if (*(char *)(iVar3 + 0x10) != '\0') {
    iVar2 = -(local_2c[0] * 2 + 9U & 0xfffffff8);
    puVar7 = (uint *)((int)local_68 + iVar2);
    puVar4 = auStack_56 + iVar2;
    uVar1 = *(undefined1 *)(iVar3 + 0x25);
    *(undefined1 **)((int)local_68 + iVar2 + 8) = auStack_44 + -local_2c[0];
    *(int **)((int)local_68 + iVar2 + 0xc) = local_2c;
    *(int *)((int)local_68 + iVar2) = param_5;
    *(undefined1 **)((int)local_68 + iVar2 + 4) = puVar4;
    FUN_08011556(param_2,*(undefined4 *)(iVar3 + 8),*(undefined4 *)(iVar3 + 0xc),uVar1);
  }
  if (((local_40 == 0) && ((int)(uVar5 << 0x16) < 0)) && (param_7 != 0)) {
    if (uVar6 == 0x40) {
      puVar4[-1] = *(undefined1 *)(iVar3 + 0x2a);
      puVar4 = puVar4 + -1;
      local_2c[0] = local_2c[0] + 1;
    }
    else {
      puVar4[-1] = *(undefined1 *)(((iVar3 + 0x26) - ((int)(uVar5 << 0x11) >> 0x1f)) + 2);
      puVar4[-2] = *(undefined1 *)(iVar3 + 0x2a);
      puVar4 = puVar4 + -2;
      local_2c[0] = local_2c[0] + 2;
    }
  }
  iVar3 = *(int *)(param_5 + 8);
  piVar8 = (int *)puVar7;
  if (local_2c[0] < iVar3) {
    iVar2 = -(iVar3 + 7U & 0xfffffff8);
    piVar8 = (int *)((int)puVar7 + iVar2);
    *(undefined1 **)((int)puVar7 + iVar2 + 4) = puVar4;
    *(int **)((int)puVar7 + iVar2 + 8) = local_2c;
    puVar4 = (undefined1 *)((int)puVar7 + iVar2 + 0x10);
    *(undefined1 **)((int)puVar7 + iVar2) = puVar4;
    FUN_0801164e(param_2,param_6,iVar3,param_5);
  }
  *(undefined4 *)(param_5 + 8) = 0;
  *piVar8 = local_2c[0];
  FUN_08011c98(local_3c,local_38,uStack_34,puVar4);
  return local_3c;
}

