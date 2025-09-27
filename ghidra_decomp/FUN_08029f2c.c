
int FUN_08029f2c(int param_1,undefined4 *param_2,byte *param_3,undefined4 *param_4)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  byte *pbVar4;
  uint uVar5;
  undefined4 *local_2b0;
  undefined1 auStack_2ac [256];
  uint local_1ac;
  undefined4 local_1a8;
  uint local_1a4;
  int local_1a0;
  int local_19c;
  undefined1 *local_198;
  int local_194;
  undefined4 local_30;
  code *local_2c;
  
  iVar1 = DAT_0802a204;
  local_1a0 = 0;
  local_19c = 0;
  local_198 = auStack_2ac;
  local_30 = DAT_0802a200;
  local_2c = DAT_0802a208;
  local_2b0 = param_4;
LAB_08029f58:
  while( true ) {
    while( true ) {
      uVar5 = (uint)*param_3;
      if (uVar5 == 0) {
        return local_1a0;
      }
      uVar3 = *(byte *)(iVar1 + uVar5) & 8;
      pbVar4 = param_3 + 1;
      if ((*(byte *)(iVar1 + uVar5) & 8) == 0) break;
      while (((param_3 = pbVar4, 0 < (int)param_2[1] ||
              (iVar2 = (*local_2c)(param_1,param_2), iVar2 == 0)) &&
             ((int)((uint)*(byte *)(iVar1 + (uint)*(byte *)*param_2) << 0x1c) < 0))) {
        local_19c = local_19c + 1;
        param_2[1] = param_2[1] + -1;
        *param_2 = (byte *)*param_2 + 1;
      }
    }
    if (uVar5 == 0x25) break;
LAB_0802a0ba:
    if (((int)param_2[1] < 1) && (iVar2 = (*local_2c)(param_1,param_2), iVar2 != 0))
    goto LAB_0802a0ea;
    if (*(byte *)*param_2 != uVar5) {
      return local_1a0;
    }
    *param_2 = (byte *)*param_2 + 1;
    local_19c = local_19c + 1;
    param_2[1] = param_2[1] + -1;
    param_3 = pbVar4;
  }
  local_1a4 = uVar3;
  local_1ac = uVar3;
  if (param_3[1] == 0x2a) {
    pbVar4 = param_3 + 2;
    local_1ac = 0x10;
  }
  while( true ) {
    uVar3 = (uint)*pbVar4;
    if (9 < uVar3 - 0x30) break;
    pbVar4 = pbVar4 + 1;
    local_1a4 = (local_1a4 * 10 + uVar3) - 0x30;
  }
  iVar2 = FUN_08005e00(DAT_0802a20c,uVar3,3);
  if (iVar2 != 0) {
    local_1ac = 1 << (iVar2 - DAT_0802a20c & 0xffU) | local_1ac;
    pbVar4 = pbVar4 + 1;
  }
  param_3 = pbVar4 + 1;
  uVar3 = (uint)*pbVar4;
  if (uVar3 < 0x79) {
    if (0x57 < uVar3) {
      switch(uVar3) {
      default:
        goto switchD_0802a026_caseD_59;
      case 0x5b:
        param_3 = (byte *)FUN_0802a8ba(auStack_2ac,param_3);
        local_1ac = local_1ac | 0x40;
        local_194 = 1;
        break;
      case 99:
        local_1ac = local_1ac | 0x40;
        local_194 = 0;
        break;
      case 100:
      case 0x75:
        local_1a8 = 10;
LAB_0802a10a:
        if (uVar3 < 0x6f) {
LAB_0802a116:
          local_194 = 3;
        }
        else {
LAB_0802a11e:
          local_194 = 4;
        }
        break;
      case 0x65:
      case 0x66:
      case 0x67:
switchD_0802a026_caseD_65:
        local_194 = 5;
        break;
      case 0x69:
        local_1a8 = 0;
        goto LAB_0802a116;
      case 0x6e:
        if (-1 < (int)(local_1ac << 0x1b)) {
          if ((int)(local_1ac << 0x1f) < 0) {
            *(short *)*local_2b0 = (short)local_19c;
            local_2b0 = local_2b0 + 1;
          }
          else {
            *(int *)*local_2b0 = local_19c;
            local_2b0 = local_2b0 + 1;
          }
        }
        goto LAB_08029f58;
      case 0x6f:
        local_1a8 = 8;
        goto LAB_0802a11e;
      case 0x70:
        local_1ac = local_1ac | 0x20;
      case 0x58:
      case 0x78:
        local_1ac = local_1ac | 0x200;
        local_1a8 = 0x10;
        goto LAB_0802a10a;
      case 0x73:
        local_194 = 2;
      }
LAB_0802a122:
      if (((int)param_2[1] < 1) && (iVar2 = (*local_2c)(param_1,param_2), iVar2 != 0))
      goto LAB_0802a0ea;
      if (-1 < (int)(local_1ac << 0x19)) {
        while ((int)((uint)*(byte *)(iVar1 + (uint)*(byte *)*param_2) << 0x1c) < 0) {
          local_19c = local_19c + 1;
          iVar2 = param_2[1];
          param_2[1] = iVar2 + -1;
          if (iVar2 + -1 < 1) {
            iVar2 = (*local_2c)(param_1,param_2);
            if (iVar2 != 0) goto LAB_0802a0ea;
          }
          else {
            *param_2 = (byte *)*param_2 + 1;
          }
        }
      }
      if (local_194 < 3) {
        iVar2 = FUN_0802a544(param_1,&local_1ac,param_2,&local_2b0);
      }
      else if (local_194 < 5) {
        iVar2 = FUN_0802a5f8(param_1,&local_1ac,param_2,&local_2b0);
      }
      else {
        iVar2 = param_1;
        if (DAT_0802a210 == 0) goto LAB_08029f58;
      }
      if (iVar2 == 1) {
        return local_1a0;
      }
      if (iVar2 == 2) {
LAB_0802a0ea:
        if ((local_1a0 == 0) || ((int)((uint)*(ushort *)(param_2 + 3) << 0x19) < 0)) {
LAB_0802a0f2:
          local_1a0 = -1;
        }
        return local_1a0;
      }
      goto LAB_08029f58;
    }
    pbVar4 = param_3;
    if (uVar3 == 0x25) goto LAB_0802a0ba;
    if (uVar3 < 0x26) {
      if (uVar3 != 0) goto switchD_0802a026_caseD_59;
      goto LAB_0802a0f2;
    }
    if (uVar3 - 0x45 < 3) goto switchD_0802a026_caseD_65;
  }
switchD_0802a026_caseD_59:
  local_194 = 3;
  local_1a8 = 10;
  goto LAB_0802a122;
}

