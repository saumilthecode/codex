
undefined4 FUN_0802a5f8(undefined4 param_1,uint *param_2,int *param_3,undefined4 *param_4)

{
  int iVar1;
  undefined4 uVar2;
  code *pcVar3;
  uint uVar4;
  byte *pbVar5;
  uint uVar6;
  undefined4 *puVar7;
  uint *puVar8;
  uint *puVar9;
  uint *puVar10;
  int unaff_r9;
  int iVar11;
  undefined4 local_34 [4];
  
  local_34[0] = *DAT_0802a7cc;
  local_34[1] = DAT_0802a7cc[1];
  local_34[2] = DAT_0802a7cc[2];
  pcVar3 = DAT_0802a7d4;
  if (param_2[6] == 3) {
    pcVar3 = DAT_0802a7d0;
  }
  uVar6 = param_2[2];
  uVar4 = uVar6 - 1;
  if (0x15c < uVar4) {
    unaff_r9 = uVar6 - 0x15d;
    uVar6 = 0x15d;
  }
  if (0x15c < uVar4) {
    param_2[2] = uVar6;
  }
  puVar10 = param_2 + 7;
  if (uVar4 < 0x15d) {
    unaff_r9 = 0;
  }
  *param_2 = *param_2 | 0xd00;
  iVar11 = 0;
  puVar9 = puVar10;
  do {
    iVar1 = FUN_08005e00(local_34[iVar11],*(undefined1 *)*param_3,2);
    puVar8 = puVar9;
    if (iVar1 != 0) {
      if (iVar11 == 1) {
        if (param_2[1] == 0) {
          param_2[1] = 8;
          *param_2 = *param_2 | 0x200;
        }
        uVar4 = *param_2 & 0xfffffaff;
LAB_0802a680:
        *param_2 = uVar4;
      }
      else if (iVar11 == 2) {
        if ((*param_2 & 0x600) == 0x200) {
          param_2[1] = 0x10;
          uVar4 = *param_2 | 0x100;
          goto LAB_0802a680;
        }
        break;
      }
      uVar4 = param_2[2];
      param_2[2] = uVar4 - 1;
      if (uVar4 != 0) {
        pbVar5 = (byte *)*param_3;
        *param_3 = (int)(pbVar5 + 1);
        puVar8 = (uint *)((int)puVar9 + 1);
        *(byte *)puVar9 = *pbVar5;
        iVar1 = param_3[1];
        param_3[1] = iVar1 + -1;
        if ((iVar1 + -1 < 1) && (iVar1 = (*(code *)param_2[0x60])(param_1,param_3), iVar1 != 0)) {
          iVar11 = 0;
          goto LAB_0802a754;
        }
      }
    }
    iVar11 = iVar11 + 1;
    puVar9 = puVar8;
  } while (iVar11 != 3);
  uVar4 = param_2[1];
  if (uVar4 == 0) {
    uVar4 = 10;
    param_2[1] = 10;
  }
  FUN_0802a8ba(param_2[5],DAT_0802a7d8 - uVar4);
  iVar11 = 0;
  while( true ) {
    puVar8 = puVar9;
    if (param_2[2] == 0) break;
    pbVar5 = (byte *)*param_3;
    uVar4 = (uint)*pbVar5;
    if (*(char *)(param_2[5] + uVar4) == '\0') break;
    if ((uVar4 == 0x30) && ((int)(*param_2 << 0x14) < 0)) {
      iVar11 = iVar11 + 1;
      if (unaff_r9 != 0) {
        unaff_r9 = unaff_r9 + -1;
        param_2[2] = param_2[2] + 1;
      }
    }
    else {
      *param_2 = *param_2 & 0xfffff6ff;
      puVar8 = (uint *)((int)puVar9 + 1);
      *(byte *)puVar9 = *pbVar5;
    }
    iVar1 = param_3[1];
    param_3[1] = iVar1 + -1;
    if (iVar1 + -1 < 1) {
      iVar1 = (*(code *)param_2[0x60])(param_1,param_3);
      if (iVar1 != 0) break;
    }
    else {
      *param_3 = *param_3 + 1;
    }
    param_2[2] = param_2[2] - 1;
    puVar9 = puVar8;
  }
LAB_0802a754:
  if ((int)(*param_2 << 0x17) < 0) {
    if (puVar10 < puVar8) {
      (*(code *)param_2[0x5f])(param_1,*(byte *)((int)puVar8 + -1),param_3);
      puVar8 = (uint *)((int)puVar8 + -1);
    }
    if (puVar8 == puVar10) {
      return 1;
    }
  }
  if ((*param_2 & 0x10) == 0) {
    *(byte *)puVar8 = 0;
    uVar2 = (*pcVar3)(param_1,puVar10,0,param_2[1]);
    puVar7 = (undefined4 *)*param_4;
    uVar4 = *param_2;
    *param_4 = puVar7 + 1;
    puVar7 = (undefined4 *)*puVar7;
    if ((int)(uVar4 << 0x1a) < 0) {
      *puVar7 = uVar2;
    }
    else if ((int)(uVar4 << 0x1f) < 0) {
      *(short *)puVar7 = (short)uVar2;
    }
    else {
      *puVar7 = uVar2;
    }
    param_2[3] = param_2[3] + 1;
  }
  param_2[4] = (uint)((int)puVar8 + param_2[4] + (iVar11 - (int)puVar10));
  return 0;
}

