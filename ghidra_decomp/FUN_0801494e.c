
undefined4 *
FUN_0801494e(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,byte *param_9)

{
  bool bVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  byte *pbVar5;
  char cVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  undefined4 local_40;
  undefined4 uStack_3c;
  undefined4 local_38;
  undefined4 local_34;
  uint local_2c [2];
  
  pbVar5 = param_9;
  local_34 = param_4;
  local_38 = param_3;
  if (*(int *)(param_7 + 0xc) << 0x1f < 0) {
    iVar7 = FUN_0801139c(param_7 + 0x6c);
    bVar3 = true;
    bVar1 = *(int *)(iVar7 + 0x20) == 0;
    bVar2 = *(int *)(iVar7 + 0x18) == 0;
    uVar9 = 0;
    bVar4 = true;
LAB_08014a0c:
    local_34 = param_4;
    if ((bVar1) && (bVar2)) {
      iVar8 = 0;
LAB_08014a28:
      if (bVar4) {
LAB_08014a2a:
        if ((*(uint *)(iVar7 + 0x20) == uVar9) && (uVar9 != 0)) {
          *pbVar5 = 0;
          if ((bVar3) && (*(uint *)(iVar7 + 0x18) == uVar9)) goto LAB_08014b0a;
          uVar9 = iVar8 << 1;
          goto LAB_08014a4e;
        }
      }
LAB_08014a72:
      if (((bVar3) && (*(uint *)(iVar7 + 0x18) == uVar9)) && (uVar9 != 0)) {
        *pbVar5 = 1;
        uVar9 = iVar8 << 1;
        goto LAB_08014a4e;
      }
      *pbVar5 = 0;
      if (iVar8 == 0) goto LAB_08014b0a;
      uVar9 = 6;
      goto LAB_08014a4e;
    }
    iVar8 = FUN_08012eba(&local_38,&param_5);
    if (iVar8 != 0) goto LAB_08014a28;
    cVar6 = FUN_08012e9c(&local_38);
    if (!bVar1) {
      if (*(char *)(*(int *)(iVar7 + 0x1c) + uVar9) != cVar6) goto LAB_08014a70;
LAB_08014a94:
      if (!bVar2) {
        bVar2 = true;
        goto LAB_08014a98;
      }
      bVar4 = bVar3;
      if (!bVar3) goto LAB_08014ab0;
      goto LAB_08014ab6;
    }
    if (bVar4) goto LAB_08014a94;
LAB_08014a70:
    if (bVar2) goto LAB_08014a72;
LAB_08014a98:
    if (*(char *)(*(int *)(iVar7 + 0x14) + uVar9) == cVar6) {
      bVar4 = bVar2;
      bVar3 = true;
LAB_08014ab6:
      uVar9 = uVar9 + 1;
      FUN_08010bc6(local_38);
      if (bVar4) {
        if (uVar9 < *(uint *)(iVar7 + 0x20)) {
          bVar1 = false;
        }
        else {
          bVar1 = true;
        }
      }
      else {
        bVar1 = true;
      }
      if (bVar3) {
        if (uVar9 < *(uint *)(iVar7 + 0x18)) {
          bVar2 = false;
        }
        else {
          bVar2 = true;
        }
      }
      else {
        bVar2 = true;
      }
      param_4 = 0xffffffff;
      goto LAB_08014a0c;
    }
LAB_08014ab0:
    bVar4 = bVar2;
    if (bVar1) {
      if (bVar4) {
        bVar3 = false;
        goto LAB_08014a2a;
      }
    }
    else {
      bVar3 = bVar1;
      if (bVar4) goto LAB_08014ab6;
    }
    *pbVar5 = bVar4;
LAB_08014b0a:
    uVar9 = 4;
LAB_08014a4e:
    *param_8 = uVar9;
    uStack_3c = local_34;
  }
  else {
    local_2c[0] = 0xffffffff;
    FUN_08014580(&local_40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_2c);
    local_38 = local_40;
    local_34 = uStack_3c;
    if (local_2c[0] < 2) {
      *pbVar5 = (byte)local_2c[0] & 1;
    }
    else {
      *pbVar5 = 1;
      *param_8 = 4;
      iVar7 = FUN_08012eba(&local_38,&param_5);
      uStack_3c = local_34;
      if (iVar7 != 0) {
        *param_8 = *param_8 | 2;
      }
    }
  }
  *param_1 = local_38;
  param_1[1] = uStack_3c;
  return param_1;
}

