
void FUN_08007900(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  byte bVar4;
  int iVar5;
  uint *puVar6;
  undefined4 uVar7;
  undefined4 extraout_r1;
  int extraout_r1_00;
  int extraout_r1_01;
  int extraout_r1_02;
  int extraout_r1_03;
  uint uVar8;
  uint uVar9;
  int *piVar10;
  byte *pbVar11;
  uint *puVar12;
  uint uVar13;
  uint uVar14;
  undefined2 local_8c;
  ushort local_8a;
  undefined4 local_88;
  undefined4 uStack_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 uStack_78;
  uint *local_74;
  uint local_70;
  uint local_6c [4];
  int local_5c;
  int local_58 [2];
  int local_50;
  char local_4c;
  char local_44;
  byte bStack_41;
  byte local_40 [32];
  
  FUN_080005d0();
  puVar1 = DAT_08007bf8;
  puVar6 = DAT_08007bf4;
  *(uint *)(DAT_08007bf0 + 0x40) = *(uint *)(DAT_08007bf0 + 0x40) | 0x10000000;
  *puVar6 = *puVar6 | 0x4000;
  uVar8 = *puVar6;
  puVar1[0x1e] = 2;
  puVar1[0x1f] = 0x2a;
  puVar1[0x19] = 1;
  puVar1[0x20] = 2;
  puVar1[0x21] = 7;
  puVar1[0x16] = 2;
  puVar1[0x1c] = 2;
  puVar1[0x1d] = 0;
  FUN_08001844(puVar1 + 0x16,uVar8 & 0x4000);
  puVar1[0x22] = 0xf;
  puVar1[0x23] = 2;
  puVar1[0x24] = 0;
  puVar1[0x25] = 0x1400;
  puVar1[0x26] = 0x1000;
  FUN_08001d30(puVar1 + 0x22,5);
  uVar8 = FUN_080006b0();
  if (0x1000 < uVar8) {
    *DAT_08007bfc = *DAT_08007bfc | 0x100;
  }
  uVar7 = DAT_08007c00;
  iVar5 = DAT_08007bf0;
  *(uint *)(DAT_08007bf0 + 0x30) = *(uint *)(DAT_08007bf0 + 0x30) | 1;
  *(uint *)(iVar5 + 0x44) = *(uint *)(iVar5 + 0x44) | 0x10;
  local_80 = 0;
  local_88 = 0x600;
  uStack_84 = 2;
  local_7c = 3;
  uStack_78 = 7;
  FUN_080011c0(uVar7,&local_88,*(uint *)(iVar5 + 0x44) & 0x10);
  uVar7 = DAT_08007c08;
  puVar1[4] = DAT_08007c04;
  puVar1[5] = 0x2580;
  puVar1[8] = 0;
  puVar1[9] = 0xc;
  puVar1[6] = 0;
  puVar1[7] = 0;
  puVar1[10] = 0;
  puVar1[0xb] = 0;
  FUN_08004328(uVar7);
  puVar2 = DAT_08007bf8;
  *(uint *)(iVar5 + 0x34) = *(uint *)(iVar5 + 0x34) | 0x40;
  uVar8 = *(uint *)(iVar5 + 0x34);
  *puVar1 = DAT_08007c0c;
  FUN_08001fa8(puVar2,extraout_r1,uVar8 & 0x40);
  uVar8 = *(uint *)(iVar5 + 0x40);
  puVar1[0x2a] = 0;
  *(uint *)(iVar5 + 0x40) = uVar8 | 0x8000;
  uVar3 = DAT_08007c14;
  uVar7 = DAT_08007c10;
  uVar8 = *(uint *)(iVar5 + 0x40);
  puVar1[0x2b] = 0;
  puVar1[0x28] = uVar7;
  puVar1[0x29] = 0x104;
  puVar1[0x2c] = 0;
  puVar1[0x2d] = 0;
  puVar1[0x2e] = 0x200;
  puVar1[0x2f] = 0x18;
  puVar1[0x30] = 0;
  puVar1[0x31] = 0;
  puVar1[0x32] = 0;
  puVar1[0x33] = 7;
  FUN_080024b0(uVar3,uVar8 & 0x8000);
LAB_08007a58:
  do {
    local_70 = 0;
    local_6c[0] = local_6c[0] & 0xffffff00;
    local_74 = local_6c;
    while( true ) {
      FUN_08004974(DAT_08007c08,local_40,1,0xffffffff);
      bVar4 = local_40[0];
      uVar8 = local_70;
      uVar13 = (uint)local_40[0];
      if (uVar13 == 10) break;
      uVar9 = local_70 + 1;
      uVar14 = local_6c[0];
      puVar6 = local_74;
      if (local_74 == local_6c) {
        if (uVar9 == 0x10) {
          puVar6 = (uint *)FUN_08008466(0x1f);
          uVar14 = 0x1e;
LAB_08007ae8:
          puVar12 = local_74;
          if (uVar8 == 1) {
            *(char *)puVar6 = (char)*local_74;
          }
          else {
            FUN_08028666(puVar6,local_74,uVar8);
          }
          goto LAB_08007ac0;
        }
      }
      else if (local_6c[0] < uVar9) {
        if ((int)uVar9 < 0) goto LAB_08007d5a;
        uVar14 = local_6c[0] * 2;
        if (uVar9 < local_6c[0] << 1) {
          if ((int)uVar14 < 0) goto LAB_08007ba0;
          iVar5 = uVar14 + 1;
        }
        else {
          iVar5 = local_70 + 2;
          uVar14 = uVar9;
          if (iVar5 < 0) {
LAB_08007ba0:
            FUN_080104ea();
            goto LAB_08007ba4;
          }
        }
        puVar6 = (uint *)FUN_08008466(iVar5);
        puVar12 = local_74;
        if (uVar8 != 0) goto LAB_08007ae8;
LAB_08007ac0:
        if (puVar12 != local_6c) {
          thunk_FUN_080249c4(puVar12,local_6c[0] + 1);
        }
      }
      local_6c[0] = uVar14;
      local_74 = puVar6;
      *(byte *)((int)local_74 + uVar8) = bVar4;
      *(undefined1 *)((int)local_74 + uVar9) = 0;
      local_70 = uVar9;
    }
    FUN_08007260(&local_5c,&local_74);
    iVar5 = local_5c;
    if (local_44 == '\0') {
LAB_08007ba4:
      FUN_080178c4(DAT_08007c1c,DAT_08007c18,0x3b);
      piVar10 = *(int **)((int)DAT_08007c1c + *(int *)(*DAT_08007c1c + -0xc) + 0x7c);
      if (piVar10 == (int *)0x0) {
        FUN_080104f6();
LAB_08007d5a:
        FUN_08010502(DAT_08007d84);
LAB_08007d60:
        FUN_080104f6();
        iVar5 = extraout_r1_03;
LAB_08007d2e:
        do {
          do {
            do {
              FUN_08006cec(&local_74,iVar5);
              FUN_08000664(1);
              FUN_08007dc2();
              iVar5 = extraout_r1_01;
            } while (local_4c == '\0');
            iVar5 = local_50 - local_58[0];
          } while (local_58[0] == 0);
          thunk_FUN_080249c4();
          iVar5 = extraout_r1_02;
        } while( true );
      }
      if ((char)piVar10[7] == '\0') {
        FUN_0800b34a(piVar10);
        if (*(code **)(*piVar10 + 0x18) != DAT_08007d80) {
          uVar13 = (**(code **)(*piVar10 + 0x18))(piVar10,10);
        }
      }
      else {
        uVar13 = (uint)*(byte *)((int)piVar10 + 0x27);
      }
      FUN_08017740(DAT_08007c1c,uVar13);
      FUN_080176b6();
LAB_08007bd8:
      if (local_74 != local_6c) {
        thunk_FUN_080249c4(local_74,local_6c[0] + 1);
      }
      FUN_08000664(1);
      goto LAB_08007a58;
    }
    if (0xe < local_5c - 1U) {
      FUN_080178c4(DAT_08007d6c,DAT_08007d68,0xe);
      piVar10 = *(int **)((int)DAT_08007d6c + *(int *)(*DAT_08007d6c + -0xc) + 0x7c);
      if (piVar10 != (int *)0x0) {
        if ((char)piVar10[7] == '\0') {
          FUN_0800b34a(piVar10);
          uVar8 = 10;
          if (*(code **)(*piVar10 + 0x18) != DAT_08007d80) {
            uVar8 = (**(code **)(*piVar10 + 0x18))(piVar10,10);
          }
        }
        else {
          uVar8 = (uint)*(byte *)((int)piVar10 + 0x27);
        }
        FUN_08017740(DAT_08007d6c,uVar8);
        FUN_080176b6();
        if ((local_4c != '\0') && (local_58[0] != 0)) {
          thunk_FUN_080249c4(local_58[0],local_50 - local_58[0]);
        }
        goto LAB_08007bd8;
      }
      FUN_080104f6();
      iVar5 = extraout_r1_00;
      goto LAB_08007d2e;
    }
    FUN_08026922(local_40,0,0x20);
    uVar8 = iVar5 << 5;
    local_8a = (ushort)((uVar8 & 0xff) << 8) | (ushort)(uVar8 >> 8) & 0xff;
    local_8c = 3;
    FUN_080017dc(DAT_08007c00,0x8000,0);
    FUN_080025bc(DAT_08007c14,&local_8c,4,0xffffffff);
    FUN_08002bec(DAT_08007c14,local_40,0x20,0xffffffff);
    FUN_080017dc(DAT_08007c00,0x8000,1);
    if (local_4c == '\0') {
      FUN_080178c4(DAT_08007d6c,DAT_08007d70,5);
      uVar7 = FUN_0801796c(DAT_08007d6c,iVar5);
      FUN_080178c4(uVar7,DAT_08007d74,0xc);
      pbVar11 = &bStack_41;
      while( true ) {
        pbVar11 = pbVar11 + 1;
        FUN_0801796c(DAT_08007d6c,*pbVar11);
        if (pbVar11 == local_40 + 0x1f) break;
        FUN_080178c4(DAT_08007d6c,DAT_08007d78,1);
      }
      FUN_080178c4(DAT_08007d6c,DAT_08007d7c,1);
      piVar10 = *(int **)((int)DAT_08007d6c + *(int *)(*DAT_08007d6c + -0xc) + 0x7c);
      if (piVar10 == (int *)0x0) goto LAB_08007d60;
      if ((char)piVar10[7] == '\0') {
        FUN_0800b34a(piVar10);
        uVar8 = 10;
        if (*(code **)(*piVar10 + 0x18) != DAT_08007d80) {
          uVar8 = (**(code **)(*piVar10 + 0x18))(piVar10,10);
        }
      }
      else {
        uVar8 = (uint)*(byte *)((int)piVar10 + 0x27);
      }
      FUN_08017740(DAT_08007d6c,uVar8);
      FUN_080176b6();
    }
    else {
      FUN_0800023c(local_40,local_58);
      if (local_58[0] != 0) {
        thunk_FUN_080249c4(local_58[0],local_50 - local_58[0]);
      }
    }
    if (local_74 != local_6c) {
      thunk_FUN_080249c4(local_74,local_6c[0] + 1);
    }
    FUN_08000664(1);
  } while( true );
}

