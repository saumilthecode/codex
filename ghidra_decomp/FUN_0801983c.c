
undefined4 *
FUN_0801983c(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            int param_5,undefined4 param_6,undefined4 *param_7)

{
  bool bVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  int *piVar7;
  int *piVar8;
  uint uVar9;
  uint uVar10;
  int iVar11;
  uint uVar12;
  undefined4 *puVar13;
  uint uVar14;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_3c;
  int local_38;
  int local_34;
  undefined4 local_30;
  undefined1 uStack_2c;
  
  piVar2 = (int *)FUN_08018e8c(param_5 + 0x6c);
  iVar3 = FUN_080193f8(param_5 + 0x6c);
  piVar8 = (int *)*param_7;
  if (*piVar8 == *(int *)(iVar3 + 0x40)) {
    local_3c = *(undefined4 *)(iVar3 + 0x3c);
    puVar13 = *(undefined4 **)(iVar3 + 0x2c);
    uVar12 = *(uint *)(iVar3 + 0x30);
    iVar4 = FUN_080187c6(piVar8);
    piVar7 = piVar8;
    if (iVar4 != 0) {
      piVar7 = piVar8 + 1;
    }
  }
  else {
    puVar13 = *(undefined4 **)(iVar3 + 0x24);
    uVar12 = *(uint *)(iVar3 + 0x28);
    local_3c = *(undefined4 *)(iVar3 + 0x38);
    piVar7 = piVar8;
  }
  iVar4 = FUN_080187c6(piVar8);
  iVar4 = (**(code **)(*piVar2 + 0x14))(piVar2,4,piVar7,piVar7 + iVar4);
  iVar4 = iVar4 - (int)piVar7 >> 2;
  local_48 = param_3;
  local_44 = param_4;
  if (iVar4 != 0) {
    local_38 = DAT_08019a88;
    FUN_0800b0a6(&local_38,iVar4 << 1);
    iVar11 = iVar4 - *(int *)(iVar3 + 0x34);
    if (0 < iVar11) {
      if (*(int *)(iVar3 + 0x34) < 0) {
        iVar11 = iVar4;
      }
      if (*(int *)(iVar3 + 0xc) == 0) {
        FUN_0800afe8(&local_38,piVar7,iVar11);
      }
      else {
        uVar5 = FUN_080187c6(local_38);
        FUN_0800af8c(&local_38,0,uVar5,iVar11 << 1,0);
        FUN_0800af44(&local_38);
        iVar6 = FUN_080190b6(local_38,*(undefined4 *)(iVar3 + 0x18),*(undefined4 *)(iVar3 + 8),
                             *(undefined4 *)(iVar3 + 0xc),piVar7,piVar7 + iVar11);
        FUN_0800af44(&local_38);
        FUN_080187ec(&local_38,iVar6 - local_38 >> 2,0xffffffff);
      }
    }
    if (0 < *(int *)(iVar3 + 0x34)) {
      FUN_0800b26e(&local_38,*(undefined4 *)(iVar3 + 0x14));
      if (iVar11 < 0) {
        FUN_0800b1c0(&local_38,-iVar11,*(undefined4 *)(iVar3 + 0x44));
      }
      else {
        iVar4 = *(int *)(iVar3 + 0x34);
        piVar7 = piVar7 + iVar11;
      }
      FUN_0800b140(&local_38,piVar7,iVar4);
    }
    uVar9 = *(uint *)(param_5 + 0xc);
    iVar4 = DAT_08019a88;
    iVar11 = FUN_080187c6(local_38);
    uVar14 = uVar9 & 0xb0;
    uVar9 = uVar9 & 0x200;
    if (uVar9 != 0) {
      uVar9 = *(uint *)(iVar3 + 0x20);
    }
    uVar9 = uVar9 + iVar11 + uVar12;
    local_34 = iVar4;
    FUN_0800b0a6(&local_34,uVar9 * 2);
    uVar10 = *(uint *)(param_5 + 8);
    bVar1 = uVar9 < uVar10 && uVar14 == 0x10;
    iVar4 = 0;
    do {
      switch(*(undefined1 *)((int)&local_3c + iVar4)) {
      case 0:
        if (bVar1) {
LAB_08019a54:
          FUN_0800b1c0(&local_34,uVar10 - uVar9,param_6);
        }
        break;
      case 1:
        uVar5 = param_6;
        if (bVar1) goto LAB_08019a54;
LAB_08019a3e:
        FUN_0800b26e(&local_34,uVar5);
        break;
      case 2:
        if (*(int *)(param_5 + 0xc) << 0x16 < 0) {
          FUN_0800b140(&local_34,*(undefined4 *)(iVar3 + 0x1c),*(undefined4 *)(iVar3 + 0x20));
        }
        break;
      case 3:
        if (uVar12 != 0) {
          uVar5 = *puVar13;
          goto LAB_08019a3e;
        }
        break;
      case 4:
        FUN_0800b0e4(&local_34,&local_38);
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 != 4);
    if (1 < uVar12) {
      FUN_0800b140(&local_34,puVar13 + 1,uVar12 - 1);
    }
    iVar3 = local_34;
    uVar12 = FUN_080187c6(local_34);
    if (uVar12 < uVar10) {
      if (uVar14 == 0x20) {
        FUN_0800b1c0(&local_34,uVar10 - uVar12,param_6);
        uVar12 = uVar10;
      }
      else {
        uVar5 = FUN_080187cc(iVar3,0,DAT_08019a8c);
        FUN_0800af8c(&local_34,uVar5,0,uVar10 - uVar12,param_6);
        uVar12 = uVar10;
      }
    }
    FUN_080195b4(&local_30,param_3,param_4,local_34,uVar12);
    local_48 = local_30;
    local_44 = CONCAT31((int3)((uint)param_4 >> 8),uStack_2c);
    FUN_08018900(local_34);
    FUN_08018900(local_38);
  }
  *(undefined4 *)(param_5 + 8) = 0;
  *param_1 = local_48;
  param_1[1] = local_44;
  return param_1;
}

