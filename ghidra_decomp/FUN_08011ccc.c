
undefined4
FUN_08011ccc(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5
            ,undefined1 param_6,int param_7)

{
  int iVar1;
  undefined1 uVar2;
  int iVar3;
  undefined1 *puVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  int *piVar8;
  int *piVar9;
  int local_70 [4];
  undefined1 auStack_5e [18];
  undefined1 auStack_4c [8];
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
  uVar5 = *(uint *)(param_5 + 0xc);
  uVar7 = uVar5 & 0x4a;
  local_44 = iVar1 + 0x26;
  piVar8 = local_70;
  iVar3 = param_7;
  if (uVar7 == 0x40) {
LAB_08011dde:
    iVar6 = 0;
  }
  else if (param_7 < 1) {
    if (uVar7 == 8) goto LAB_08011dde;
    iVar6 = 1;
    iVar3 = -param_7;
  }
  else {
    iVar6 = uVar7 - 8;
    if (iVar6 != 0) {
      iVar6 = 1;
    }
  }
  local_70[0] = iVar6;
  local_2c[0] = FUN_0801166a(auStack_4c,iVar3,iVar1 + 0x26,uVar5);
  puVar4 = auStack_4c + -local_2c[0];
  if (*(char *)(iVar1 + 0x10) != '\0') {
    iVar3 = -(local_2c[0] * 2 + 9U & 0xfffffff8);
    piVar8 = (int *)((int)local_70 + iVar3);
    puVar4 = auStack_5e + iVar3;
    uVar2 = *(undefined1 *)(iVar1 + 0x25);
    *(undefined1 **)((int)local_70 + iVar3 + 8) = auStack_4c + -local_2c[0];
    *(int **)((int)local_70 + iVar3 + 0xc) = local_2c;
    *(int *)((int)local_70 + iVar3) = param_5;
    *(undefined1 **)((int)local_70 + iVar3 + 4) = puVar4;
    FUN_08011556(local_40,*(undefined4 *)(iVar1 + 8),*(undefined4 *)(iVar1 + 0xc),uVar2);
  }
  if (iVar6 == 0) {
    if ((-1 < (int)(uVar5 << 0x16)) || (param_7 == 0)) goto LAB_08011d86;
    if (uVar7 != 0x40) {
      puVar4[-1] = *(undefined1 *)((iVar1 - ((int)(uVar5 << 0x11) >> 0x1f)) + 0x28);
      puVar4[-2] = *(undefined1 *)(iVar1 + 0x2a);
      puVar4 = puVar4 + -2;
      local_2c[0] = local_2c[0] + 2;
      goto LAB_08011d86;
    }
    uVar2 = *(undefined1 *)(iVar1 + 0x2a);
  }
  else if (param_7 < 0) {
    uVar2 = *(undefined1 *)(iVar1 + 0x26);
  }
  else {
    if (-1 < (int)(uVar5 << 0x14)) goto LAB_08011d86;
    uVar2 = *(undefined1 *)(iVar1 + 0x27);
  }
  puVar4[-1] = uVar2;
  puVar4 = puVar4 + -1;
  local_2c[0] = local_2c[0] + 1;
LAB_08011d86:
  iVar3 = *(int *)(param_5 + 8);
  piVar9 = piVar8;
  if (local_2c[0] < iVar3) {
    iVar1 = -(iVar3 + 7U & 0xfffffff8);
    piVar9 = (int *)((int)piVar8 + iVar1);
    *(undefined1 **)((int)piVar8 + iVar1 + 4) = puVar4;
    *(int **)((int)piVar8 + iVar1 + 8) = local_2c;
    puVar4 = (undefined1 *)((int)piVar8 + iVar1 + 0x10);
    *(undefined1 **)((int)piVar8 + iVar1) = puVar4;
    FUN_0801164e(local_40,param_6,iVar3,param_5);
  }
  *(undefined4 *)(param_5 + 8) = 0;
  *piVar9 = local_2c[0];
  FUN_08011c98(local_3c,local_38,uStack_34,puVar4);
  return local_3c;
}

