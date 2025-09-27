
undefined4
FUN_080120d0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5
            ,undefined1 param_6,int param_7,int param_8)

{
  int iVar1;
  undefined1 uVar2;
  int iVar3;
  int iVar4;
  undefined1 *puVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  int *piVar9;
  int *piVar10;
  int local_80 [4];
  undefined1 auStack_6e [38];
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
  iVar1 = FUN_0801139c(param_5 + 0x6c);
  local_44 = iVar1 + 0x26;
  uVar6 = *(uint *)(param_5 + 0xc);
  uVar8 = uVar6 & 0x4a;
  piVar9 = local_80;
  iVar3 = param_7;
  iVar4 = param_8;
  if (uVar8 == 0x40) {
LAB_080121f4:
    iVar7 = 0;
  }
  else if (param_8 < (int)(uint)(param_7 == 0)) {
    if (uVar8 == 8) goto LAB_080121f4;
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
  local_80[0] = iVar1 + 0x26;
  local_80[1] = uVar6;
  local_80[2] = iVar7;
  local_2c[0] = FUN_080116cc(auStack_48,local_80[0],iVar3,iVar4);
  puVar5 = auStack_48 + -local_2c[0];
  if (*(char *)(iVar1 + 0x10) != '\0') {
    iVar3 = -(local_2c[0] * 2 + 9U & 0xfffffff8);
    piVar9 = (int *)((int)local_80 + iVar3);
    uVar2 = *(undefined1 *)(iVar1 + 0x25);
    *(undefined1 **)((int)local_80 + iVar3 + 8) = puVar5;
    *(int **)((int)local_80 + iVar3 + 0xc) = local_2c;
    puVar5 = auStack_6e + iVar3;
    *(undefined1 **)((int)local_80 + iVar3 + 4) = puVar5;
    *(int *)((int)local_80 + iVar3) = param_5;
    FUN_08011556(local_40,*(undefined4 *)(iVar1 + 8),*(undefined4 *)(iVar1 + 0xc),uVar2);
  }
  if (iVar7 == 0) {
    if ((-1 < (int)(uVar6 << 0x16)) || (param_7 == 0 && param_8 == 0)) goto LAB_08012194;
    if (uVar8 != 0x40) {
      puVar5[-1] = *(undefined1 *)((iVar1 - ((int)(uVar6 << 0x11) >> 0x1f)) + 0x28);
      puVar5[-2] = *(undefined1 *)(iVar1 + 0x2a);
      puVar5 = puVar5 + -2;
      local_2c[0] = local_2c[0] + 2;
      goto LAB_08012194;
    }
    uVar2 = *(undefined1 *)(iVar1 + 0x2a);
  }
  else if (param_8 < 0) {
    uVar2 = *(undefined1 *)(iVar1 + 0x26);
  }
  else {
    if (-1 < (int)(uVar6 << 0x14)) goto LAB_08012194;
    uVar2 = *(undefined1 *)(iVar1 + 0x27);
  }
  puVar5[-1] = uVar2;
  puVar5 = puVar5 + -1;
  local_2c[0] = local_2c[0] + 1;
LAB_08012194:
  iVar3 = *(int *)(param_5 + 8);
  piVar10 = piVar9;
  if (local_2c[0] < iVar3) {
    iVar4 = -(iVar3 + 7U & 0xfffffff8);
    piVar10 = (int *)((int)piVar9 + iVar4);
    *(undefined1 **)((int)piVar9 + iVar4 + 4) = puVar5;
    *(int **)((int)piVar9 + iVar4 + 8) = local_2c;
    puVar5 = (undefined1 *)((int)piVar9 + iVar4 + 0x10);
    *(undefined1 **)((int)piVar9 + iVar4) = puVar5;
    FUN_0801164e(local_40,param_6,iVar3,param_5);
  }
  *(undefined4 *)(param_5 + 8) = 0;
  *piVar10 = local_2c[0];
  FUN_08011c98(local_3c,local_38,uStack_34,puVar5);
  return local_3c;
}

