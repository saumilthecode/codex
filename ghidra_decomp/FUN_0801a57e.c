
undefined4
FUN_0801a57e(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5
            ,undefined4 param_6,undefined1 param_7,undefined4 param_8,int param_9,
            undefined4 param_10)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  int *piVar4;
  int *piVar5;
  char *pcVar6;
  int iVar7;
  int *piVar8;
  int *piVar9;
  uint uVar10;
  int iVar11;
  int *piVar12;
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
  iVar2 = FUN_08018fd4(param_5 + 0x6c);
  iVar7 = *(int *)(param_5 + 4);
  if (iVar7 < 0) {
    iVar7 = 6;
  }
  FUN_0801faf0(param_5,auStack_38,param_7);
  uVar10 = *(uint *)(param_5 + 0xc) & 0x104;
  pcVar6 = acStack_80;
  if (uVar10 == 0x104) {
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
  piVar12 = local_90;
  if (0x2c < local_40) {
    iVar11 = local_40 + 1;
    iVar1 = -(local_40 + 8U & 0xfffffff8);
    piVar12 = (int *)((int)local_90 + iVar1);
    pcVar6 = acStack_80 + iVar1;
    if (uVar10 == 0x104) {
      local_3c = FUN_08008940();
      *(int *)((int)local_90 + iVar1) = param_9;
      *(undefined4 *)((int)local_90 + iVar1 + 4) = param_10;
      local_40 = FUN_0800d708(&local_3c,pcVar6,iVar11,auStack_38);
    }
    else {
      local_3c = FUN_08008940();
      *(int *)((int)local_90 + iVar1 + 8) = param_9;
      *(undefined4 *)(acStack_80 + iVar1 + -4) = param_10;
      *(int *)((int)local_90 + iVar1) = iVar7;
      local_40 = FUN_0800d708(&local_3c,pcVar6,iVar11,auStack_38);
      piVar12 = (int *)((int)local_90 + iVar1);
    }
  }
  uVar3 = FUN_08018e8c(param_5 + 0x6c);
  iVar1 = -(local_40 * 4 + 7U & 0xfffffff8);
  piVar8 = (int *)((int)piVar12 + iVar1 + 0x10);
  FUN_08018820(uVar3,pcVar6,pcVar6 + local_40,piVar8);
  iVar7 = local_40;
  if (local_40 == 0) {
    piVar4 = (int *)0x0;
  }
  else {
    piVar4 = (int *)FUN_08005e00(pcVar6,0x2e,local_40);
    if (piVar4 != (int *)0x0) {
      *(undefined4 *)((int)piVar12 + ((int)piVar4 - (int)pcVar6) * 4 + iVar1 + 0x10) =
           *(undefined4 *)(iVar2 + 0x24);
      piVar4 = piVar8 + ((int)piVar4 - (int)pcVar6);
    }
  }
  piVar9 = piVar8;
  piVar5 = (int *)((int)piVar12 + iVar1);
  if ((*(char *)(iVar2 + 0x10) != '\0') &&
     (((piVar4 != (int *)0x0 || (iVar7 < 3)) ||
      ((piVar5 = (int *)((int)piVar12 + iVar1), (byte)pcVar6[1] < 0x3a &&
       ((piVar5 = (int *)((int)piVar12 + iVar1), (byte)pcVar6[2] - 0x30 < 10 &&
        (piVar5 = (int *)((int)piVar12 + iVar1), 0x2f < (byte)pcVar6[1])))))))) {
    piVar5 = (int *)((int)piVar12 + iVar7 * -8 + iVar1);
    piVar9 = piVar5 + 4;
    if ((*pcVar6 == '-') || (*pcVar6 == '+')) {
      *piVar9 = *piVar8;
      local_40 = iVar7 + -1;
      iVar7 = 1;
    }
    else {
      iVar7 = 0;
    }
    piVar5[3] = (int)&local_40;
    piVar5[2] = (int)(piVar8 + iVar7);
    *piVar5 = (int)piVar4;
    piVar5[1] = (int)(piVar9 + iVar7);
    FUN_0801915a(local_50,*(undefined4 *)(iVar2 + 8),*(undefined4 *)(iVar2 + 0xc),
                 *(undefined4 *)(iVar2 + 0x28));
    iVar7 = iVar7 + local_40;
    local_40 = iVar7;
  }
  iVar2 = *(int *)(param_5 + 8);
  piVar12 = piVar5;
  if (iVar7 < iVar2) {
    iVar7 = -(iVar2 * 4 + 7U & 0xfffffff8);
    piVar12 = (int *)((int)piVar5 + iVar7);
    *(int **)((int)piVar5 + iVar7 + 4) = piVar9;
    *(int **)((int)piVar5 + iVar7 + 8) = &local_40;
    piVar9 = (int *)((int)piVar5 + iVar7 + 0x10);
    *(int **)((int)piVar5 + iVar7) = piVar9;
    FUN_08019c94(local_50,param_6,iVar2,param_5);
  }
  *(undefined4 *)(param_5 + 8) = 0;
  *piVar12 = local_40;
  FUN_080195b4(local_4c,local_48,uStack_44,piVar9);
  return local_4c;
}

