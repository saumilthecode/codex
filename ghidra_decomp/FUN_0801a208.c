
undefined4
FUN_0801a208(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5
            ,undefined4 param_6,int param_7,int param_8)

{
  int iVar1;
  int iVar2;
  undefined1 *puVar3;
  uint uVar4;
  uint uVar5;
  int *piVar6;
  int *piVar7;
  undefined8 uVar8;
  int local_f8 [4];
  undefined1 auStack_e8 [8];
  undefined1 auStack_e0 [152];
  uint local_48;
  int local_44;
  int local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 uStack_34;
  int local_2c [2];
  
  local_40 = param_7;
  local_44 = param_8;
  local_3c = param_1;
  local_38 = param_3;
  uStack_34 = param_4;
  uVar8 = FUN_08018fd4(param_5 + 0x6c);
  iVar2 = (int)uVar8;
  uVar4 = *(uint *)(param_5 + 0xc);
  uVar5 = uVar4 & 0x4a;
  piVar6 = local_f8;
  local_f8[2] = (int)(uVar5 != 0x40 && uVar5 != 8);
  local_f8[0] = iVar2 + 0x2c;
  local_f8[1] = uVar4;
  local_48 = local_f8[2];
  local_2c[0] = FUN_08019236(&local_48,(int)((ulonglong)uVar8 >> 0x20),local_40,local_44);
  puVar3 = auStack_e8 + (0x28 - local_2c[0]) * 4;
  if (*(char *)(iVar2 + 0x10) != '\0') {
    iVar1 = -(local_2c[0] * 8 + 8);
    piVar6 = (int *)((int)local_f8 + iVar1);
    puVar3 = auStack_e0 + iVar1;
    *(undefined1 **)((int)local_f8 + iVar1 + 8) = auStack_e8 + (0x28 - local_2c[0]) * 4;
    *(int **)((int)local_f8 + iVar1 + 0xc) = local_2c;
    *(int *)((int)local_f8 + iVar1) = param_5;
    *(undefined1 **)((int)local_f8 + iVar1 + 4) = puVar3;
    FUN_080191a2(param_2,*(undefined4 *)(iVar2 + 8),*(undefined4 *)(iVar2 + 0xc),
                 *(undefined4 *)(iVar2 + 0x28));
  }
  if (((local_48 == 0) && ((int)(uVar4 << 0x16) < 0)) && (local_40 != 0 || local_44 != 0)) {
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
  piVar7 = piVar6;
  if (local_2c[0] < iVar2) {
    iVar1 = -(iVar2 * 4 + 7U & 0xfffffff8);
    piVar7 = (int *)((int)piVar6 + iVar1);
    *(undefined1 **)((int)piVar6 + iVar1 + 4) = puVar3;
    *(int **)((int)piVar6 + iVar1 + 8) = local_2c;
    puVar3 = (undefined1 *)((int)piVar6 + iVar1 + 0x10);
    *(undefined1 **)((int)piVar6 + iVar1) = puVar3;
    FUN_08019c94(param_2,param_6,iVar2,param_5);
  }
  *(undefined4 *)(param_5 + 8) = 0;
  *piVar7 = local_2c[0];
  FUN_080195b4(local_3c,local_38,uStack_34,puVar3);
  return local_3c;
}

