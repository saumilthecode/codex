
int FUN_0802b110(int param_1,int param_2,byte *param_3,uint *param_4)

{
  int iVar1;
  int iVar2;
  uint *puVar3;
  bool bVar4;
  uint uVar5;
  byte *pbVar6;
  int unaff_r7;
  byte *pbVar7;
  int iVar8;
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
  
  if ((param_1 != 0) && (*(int *)(param_1 + 0x20) == 0)) {
    FUN_08025ec4();
  }
  if ((-1 < *(int *)(param_2 + 100) << 0x1f) &&
     (-1 < (int)((uint)*(ushort *)(param_2 + 0xc) << 0x16))) {
    FUN_08028650(*(undefined4 *)(param_2 + 0x58));
  }
  if (((-1 < (int)((uint)*(ushort *)(param_2 + 0xc) << 0x1c)) || (*(int *)(param_2 + 0x10) == 0)) &&
     (iVar1 = FUN_08026644(param_1,param_2), iVar1 != 0)) {
    if ((-1 < *(int *)(param_2 + 100) << 0x1f) &&
       (-1 < (int)((uint)*(ushort *)(param_2 + 0xc) << 0x16))) {
      FUN_08028654(*(undefined4 *)(param_2 + 0x58));
    }
    return -1;
  }
  iVar1 = DAT_0802b32c;
  local_74 = 0;
  local_6f = 0x20;
  local_6e = 0x30;
  pbVar7 = param_3;
  local_8c = param_4;
LAB_0802b18a:
  pbVar6 = pbVar7;
  if (*pbVar6 != 0) goto code_r0x0802b192;
  goto LAB_0802b196;
code_r0x0802b192:
  pbVar7 = pbVar6 + 1;
  if (*pbVar6 != 0x25) goto LAB_0802b18a;
LAB_0802b196:
  iVar8 = (int)pbVar6 - (int)param_3;
  if (iVar8 != 0) {
    iVar2 = FUN_0802b0ea(param_1,param_2,param_3,iVar8);
    if (iVar2 == -1) {
LAB_0802b2fc:
      if ((-1 < *(int *)(param_2 + 100) << 0x1f) &&
         (-1 < (int)((uint)*(ushort *)(param_2 + 0xc) << 0x16))) {
        FUN_08028654(*(undefined4 *)(param_2 + 0x58));
      }
      if ((int)((uint)*(ushort *)(param_2 + 0xc) << 0x19) < 0) {
        return -1;
      }
      return local_74;
    }
    local_74 = local_74 + iVar8;
  }
  if (*pbVar6 == 0) goto LAB_0802b2fc;
  local_84 = 0xffffffff;
  uStack_80 = 0;
  local_88 = 0;
  local_7c = 0;
  local_45 = 0;
  local_30 = 0;
  pbVar7 = pbVar6 + 1;
  while( true ) {
    pbVar6 = pbVar7 + 1;
    iVar2 = FUN_08005e00(DAT_0802b32c,*pbVar7,5);
    iVar8 = DAT_0802b330;
    if (iVar2 == 0) break;
    local_88 = 1 << (iVar2 - iVar1 & 0xffU) | local_88;
    pbVar7 = pbVar6;
  }
  if ((int)(local_88 << 0x1b) < 0) {
    local_45 = 0x20;
  }
  if ((int)(local_88 << 0x1c) < 0) {
    local_45 = 0x2b;
  }
  if (*pbVar7 == 0x2a) {
    puVar3 = local_8c + 1;
    local_7c = *local_8c;
    local_8c = puVar3;
    if ((int)local_7c < 0) {
      local_7c = -local_7c;
      local_88 = local_88 | 2;
    }
  }
  else {
    bVar4 = false;
    uVar5 = local_7c;
    pbVar6 = pbVar7;
    while( true ) {
      if (9 < *pbVar6 - 0x30) break;
      uVar5 = uVar5 * 10 + (*pbVar6 - 0x30);
      bVar4 = true;
      pbVar6 = pbVar6 + 1;
    }
    if (bVar4) {
      local_7c = uVar5;
    }
  }
  if (*pbVar6 == 0x2e) {
    if (pbVar6[1] == 0x2a) {
      uVar5 = *local_8c;
      pbVar6 = pbVar6 + 2;
      local_8c = local_8c + 1;
      local_84 = uVar5 | (int)uVar5 >> 0x1f;
    }
    else {
      bVar4 = false;
      local_84 = 0;
      uVar5 = 0;
      while( true ) {
        pbVar6 = pbVar6 + 1;
        if (9 < *pbVar6 - 0x30) break;
        uVar5 = uVar5 * 10 + (*pbVar6 - 0x30);
        bVar4 = true;
      }
      if (bVar4) {
        local_84 = uVar5;
      }
    }
  }
  iVar2 = FUN_08005e00(DAT_0802b330,*pbVar6,3);
  if (iVar2 != 0) {
    local_88 = local_88 | 0x40 << (iVar2 - iVar8 & 0xffU);
    pbVar6 = pbVar6 + 1;
  }
  param_3 = pbVar6 + 1;
  local_70 = *pbVar6;
  iVar8 = FUN_08005e00(DAT_0802b334,local_70,6);
  if (iVar8 == 0) {
    iVar8 = FUN_0802a304(param_1,&local_88,param_2,DAT_0802b33c,&local_8c);
  }
  else {
    iVar8 = param_1;
    if (DAT_0802b338 == 0) {
      local_8c = (uint *)(((int)local_8c + 7U & 0xfffffff8) + 8);
      iVar8 = unaff_r7;
      goto LAB_0802b2aa;
    }
  }
  if (iVar8 == -1) goto LAB_0802b2fc;
LAB_0802b2aa:
  local_74 = local_74 + iVar8;
  pbVar7 = param_3;
  unaff_r7 = iVar8;
  goto LAB_0802b18a;
}

