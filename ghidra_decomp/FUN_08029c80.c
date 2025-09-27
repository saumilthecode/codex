
int FUN_08029c80(undefined4 *param_1,int *param_2,byte *param_3,uint *param_4)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  uint *puVar4;
  bool bVar5;
  uint uVar6;
  byte *pbVar7;
  undefined4 *unaff_r6;
  byte *pbVar8;
  int iVar9;
  uint *local_8c;
  uint local_88;
  uint local_84;
  undefined4 uStack_80;
  uint local_7c;
  int local_74;
  byte local_70;
  undefined1 local_6f;
  undefined1 local_6e;
  undefined1 local_45;
  undefined4 local_30;
  
  if (((int)((uint)*(ushort *)(param_2 + 3) << 0x18) < 0) && (param_2[4] == 0)) {
    iVar1 = FUN_08024a18(param_1,0x40);
    *param_2 = iVar1;
    param_2[4] = iVar1;
    if (iVar1 == 0) {
      *param_1 = 0xc;
      return -1;
    }
    param_2[5] = 0x40;
  }
  iVar1 = DAT_08029e64;
  local_74 = 0;
  local_6f = 0x20;
  local_6e = 0x30;
  pbVar8 = param_3;
  local_8c = param_4;
LAB_08029cd4:
  pbVar7 = pbVar8;
  if (*pbVar7 != 0) goto code_r0x08029cdc;
  goto LAB_08029ce0;
code_r0x08029cdc:
  pbVar8 = pbVar7 + 1;
  if (*pbVar7 != 0x25) goto LAB_08029cd4;
LAB_08029ce0:
  iVar9 = (int)pbVar7 - (int)param_3;
  if (iVar9 != 0) {
    iVar2 = FUN_08029bc0(param_1,param_2,param_3,iVar9);
    if (iVar2 == -1) {
LAB_08029e46:
      if ((int)((uint)*(ushort *)(param_2 + 3) << 0x19) < 0) {
        return -1;
      }
      return local_74;
    }
    local_74 = local_74 + iVar9;
  }
  if (*pbVar7 == 0) goto LAB_08029e46;
  local_84 = 0xffffffff;
  uStack_80 = 0;
  local_88 = 0;
  local_7c = 0;
  local_45 = 0;
  local_30 = 0;
  pbVar8 = pbVar7 + 1;
  while( true ) {
    pbVar7 = pbVar8 + 1;
    iVar2 = FUN_08005e00(DAT_08029e64,*pbVar8,5);
    iVar9 = DAT_08029e68;
    if (iVar2 == 0) break;
    local_88 = 1 << (iVar2 - iVar1 & 0xffU) | local_88;
    pbVar8 = pbVar7;
  }
  if ((int)(local_88 << 0x1b) < 0) {
    local_45 = 0x20;
  }
  if ((int)(local_88 << 0x1c) < 0) {
    local_45 = 0x2b;
  }
  if (*pbVar8 == 0x2a) {
    puVar4 = local_8c + 1;
    local_7c = *local_8c;
    local_8c = puVar4;
    if ((int)local_7c < 0) {
      local_7c = -local_7c;
      local_88 = local_88 | 2;
    }
  }
  else {
    bVar5 = false;
    uVar6 = local_7c;
    pbVar7 = pbVar8;
    while( true ) {
      if (9 < *pbVar7 - 0x30) break;
      uVar6 = uVar6 * 10 + (*pbVar7 - 0x30);
      bVar5 = true;
      pbVar7 = pbVar7 + 1;
    }
    if (bVar5) {
      local_7c = uVar6;
    }
  }
  if (*pbVar7 == 0x2e) {
    if (pbVar7[1] == 0x2a) {
      uVar6 = *local_8c;
      pbVar7 = pbVar7 + 2;
      local_8c = local_8c + 1;
      local_84 = uVar6 | (int)uVar6 >> 0x1f;
    }
    else {
      bVar5 = false;
      local_84 = 0;
      uVar6 = 0;
      while( true ) {
        pbVar7 = pbVar7 + 1;
        if (9 < *pbVar7 - 0x30) break;
        uVar6 = uVar6 * 10 + (*pbVar7 - 0x30);
        bVar5 = true;
      }
      if (bVar5) {
        local_84 = uVar6;
      }
    }
  }
  iVar2 = FUN_08005e00(DAT_08029e68,*pbVar7,3);
  if (iVar2 != 0) {
    local_88 = local_88 | 0x40 << (iVar2 - iVar9 & 0xffU);
    pbVar7 = pbVar7 + 1;
  }
  param_3 = pbVar7 + 1;
  local_70 = *pbVar7;
  iVar9 = FUN_08005e00(DAT_08029e6c,local_70,6);
  if (iVar9 == 0) {
    puVar3 = (undefined4 *)FUN_0802a304(param_1,&local_88,param_2,DAT_08029e74,&local_8c);
  }
  else {
    puVar3 = param_1;
    if (DAT_08029e70 == 0) {
      local_8c = (uint *)(((int)local_8c + 7U & 0xfffffff8) + 8);
      puVar3 = unaff_r6;
      goto LAB_08029df4;
    }
  }
  if (puVar3 == (undefined4 *)0xffffffff) goto LAB_08029e46;
LAB_08029df4:
  local_74 = local_74 + (int)puVar3;
  pbVar8 = param_3;
  unaff_r6 = puVar3;
  goto LAB_08029cd4;
}

