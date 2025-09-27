
undefined4 *
FUN_0800f7c0(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,undefined4 param_9)

{
  int *piVar1;
  uint *puVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  uint uVar11;
  uint local_90;
  uint local_8c;
  uint local_88;
  uint local_84;
  uint local_80;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_5c;
  undefined1 *local_58;
  int local_54;
  undefined1 local_50 [16];
  char *local_40;
  uint local_3c;
  char local_38 [20];
  
  puVar2 = param_8;
  iVar8 = param_7 + 0x6c;
  local_68 = param_3;
  local_64 = param_4;
  uVar3 = FUN_08018e8c(iVar8);
  iVar8 = FUN_0800d608(iVar8);
  if (*(int *)(iVar8 + 0x28) == 0) {
    local_84 = 0;
  }
  else {
    local_84 = *(uint *)(iVar8 + 0x30);
    if (local_84 != 0) {
      local_84 = 1;
    }
  }
  local_58 = local_50;
  local_54 = 0;
  local_50[0] = 0;
  if (*(char *)(iVar8 + 0x10) != '\0') {
    FUN_08017ea8(&local_58,0x20);
  }
  iVar10 = 0;
  local_40 = local_38;
  local_3c = 0;
  local_38[0] = '\0';
  FUN_08017ea8(&local_40,0x20);
  local_8c = 0;
  local_88 = 0;
  local_5c = *(undefined4 *)(iVar8 + 0x3c);
  local_90 = 0;
  uVar11 = 0;
  local_80 = 0;
LAB_0800f842:
  do {
    piVar1 = DAT_0800fb00;
    switch(*(undefined1 *)((int)&local_5c + iVar10)) {
    case 0:
      uVar9 = 1;
      goto LAB_0800fad0;
    case 1:
      local_68 = param_3;
      local_64 = param_4;
      iVar5 = FUN_0800e0fc(&local_68,&param_5);
      if (iVar5 == 0) {
        uVar9 = 0;
        param_3 = local_68;
        param_4 = local_64;
      }
      else {
        uVar7 = FUN_0800e0b8(&local_68);
        param_4 = local_64;
        param_3 = local_68;
        uVar9 = FUN_0800e09a(uVar3,8,uVar7);
        if (uVar9 != 0) {
          FUN_0800d316(param_3);
          param_4 = 0xffffffff;
        }
      }
LAB_0800fad0:
      if (iVar10 == 3) goto LAB_0800f92a;
      while (local_68 = param_3, local_64 = param_4, iVar5 = FUN_0800e0fc(&local_68,&param_5),
            param_3 = local_68, param_4 = local_64, iVar5 != 0) {
        uVar7 = FUN_0800e0b8(&local_68);
        param_4 = local_64;
        param_3 = local_68;
        iVar5 = FUN_0800e09a(uVar3,8,uVar7);
        if (iVar5 == 0) break;
        FUN_0800d316(param_3);
        param_4 = 0xffffffff;
      }
      iVar10 = iVar10 + 1;
      goto LAB_0800faea;
    case 2:
      if (((*(int *)(param_7 + 0xc) << 0x16 < 0) || (1 < local_8c)) || (iVar10 == 0)) {
LAB_0800f8d2:
        iVar5 = *(int *)(iVar8 + 0x20);
        iVar6 = 0;
        while (local_68 = param_3, local_64 = param_4, uVar9 = FUN_0800e0fc(&local_68,&param_5),
              param_3 = local_68, param_4 = local_64, uVar9 != 0) {
          if (iVar6 == iVar5) goto LAB_0800f922;
          iVar4 = FUN_0800e0b8(&local_68);
          param_3 = local_68;
          if (*(int *)(*(int *)(iVar8 + 0x1c) + iVar6 * 4) != iVar4) goto LAB_0800f90c;
          FUN_0800d316(local_68);
          iVar6 = iVar6 + 1;
          param_4 = 0xffffffff;
        }
        if (iVar6 == iVar5) goto switchD_0800f84c_default;
LAB_0800f90c:
        param_3 = local_68;
        param_4 = local_64;
        if (iVar6 == 0) {
          uVar9 = ((uint)*(byte *)(param_7 + 0xd) << 0x1e) >> 0x1f ^ 1;
        }
        else {
          uVar9 = 0;
        }
        break;
      }
      if (iVar10 == 1) {
        if (((local_84 != 0) || ((char)local_5c == '\x03')) || (local_5c._2_1_ == '\x01'))
        goto LAB_0800f8d2;
        iVar10 = 2;
      }
      else {
        if (iVar10 != 2) {
          uVar9 = 1;
          goto LAB_0800f92a;
        }
        if (local_5c._3_1_ == '\x04') goto LAB_0800f8d2;
        if (local_84 != 0) {
          if (local_5c._3_1_ == '\x03') goto LAB_0800f8d2;
          iVar10 = 3;
          uVar9 = local_84;
          goto LAB_0800faea;
        }
        iVar10 = 3;
      }
      goto LAB_0800f842;
    case 3:
      if (((*(int *)(iVar8 + 0x28) == 0) ||
          (local_68 = param_3, local_64 = param_4, uVar9 = FUN_0800e0fc(&local_68,&param_5),
          param_3 = local_68, param_4 = local_64, uVar9 == 0)) ||
         (iVar5 = FUN_0800e0b8(&local_68), param_3 = local_68, param_4 = local_64,
         **(int **)(iVar8 + 0x24) != iVar5)) {
        if (((*(int *)(iVar8 + 0x30) == 0) ||
            (local_68 = param_3, local_64 = param_4, uVar9 = FUN_0800e0fc(&local_68,&param_5),
            param_3 = local_68, param_4 = local_64, uVar9 == 0)) ||
           (iVar5 = FUN_0800e0b8(&local_68), param_3 = local_68, param_4 = local_64,
           **(int **)(iVar8 + 0x2c) != iVar5)) {
          if ((*(int *)(iVar8 + 0x28) == 0) || (*(int *)(iVar8 + 0x30) != 0)) {
            uVar9 = local_84 ^ 1;
          }
          else {
            uVar9 = 1;
            local_80 = 1;
          }
          break;
        }
        local_8c = *(uint *)(iVar8 + 0x30);
        FUN_0800d316(local_68);
        local_80 = uVar9;
      }
      else {
        local_8c = *(uint *)(iVar8 + 0x28);
        FUN_0800d316(local_68);
      }
      param_4 = 0xffffffff;
      break;
    case 4:
      while (local_68 = param_3, local_64 = param_4, uVar9 = FUN_0800e0fc(&local_68,&param_5),
            uVar9 != 0) {
        iVar5 = FUN_0800e0b8(&local_68);
        param_4 = local_64;
        param_3 = local_68;
        iVar6 = FUN_080269a2(iVar8 + 0x44,iVar5,10);
        if (iVar6 == 0) {
          if ((*(int *)(iVar8 + 0x14) == iVar5) && (local_90 == 0)) {
            if (*(int *)(iVar8 + 0x34) < 1) goto LAB_0800f87c;
            local_88 = uVar11;
            uVar11 = 0;
            local_90 = uVar9;
          }
          else {
            if ((*(byte *)(iVar8 + 0x10) == 0) ||
               ((uVar9 = (uint)*(byte *)(iVar8 + 0x10), *(int *)(iVar8 + 0x18) != iVar5 ||
                (uVar9 = local_90, local_90 != 0)))) goto LAB_0800f87c;
            if (uVar11 == 0) {
              uVar9 = 0;
              goto LAB_0800f87c;
            }
            FUN_08017ede(&local_58,uVar11 & 0xff);
            uVar11 = 0;
          }
        }
        else {
          FUN_08017ede(&local_40,*(undefined1 *)(*piVar1 + (iVar6 - (iVar8 + 0x40) >> 2)));
          uVar11 = uVar11 + 1;
        }
        FUN_0800d316(param_3);
        param_4 = 0xffffffff;
      }
      param_3 = local_68;
      param_4 = local_64;
      uVar9 = 1;
LAB_0800f87c:
      if (local_3c == 0) {
        uVar9 = 0;
      }
      else {
        uVar9 = uVar9 & 1;
      }
      break;
    default:
switchD_0800f84c_default:
      uVar9 = 1;
    }
LAB_0800f922:
    iVar10 = iVar10 + 1;
    if (iVar10 == 4) {
LAB_0800f92a:
      if (local_8c < 2) {
        if (uVar9 != 0) goto LAB_0800fb6c;
      }
      else if (uVar9 != 0) {
        if (local_80 == 0) {
          iVar10 = *(int *)(iVar8 + 0x24);
        }
        else {
          iVar10 = *(int *)(iVar8 + 0x2c);
        }
        uVar9 = 1;
        break;
      }
      goto LAB_0800faf0;
    }
LAB_0800faea:
    if (uVar9 == 0) goto LAB_0800faf0;
  } while( true );
LAB_0800f944:
  local_68 = param_3;
  local_64 = param_4;
  iVar5 = FUN_0800e0fc(&local_68,&param_5);
  param_3 = local_68;
  param_4 = local_64;
  if (iVar5 == 0) goto LAB_0800fb68;
  if (uVar9 == local_8c) goto LAB_0800fb6c;
  iVar5 = FUN_0800e0b8(&local_68);
  param_3 = local_68;
  param_4 = local_64;
  if (*(int *)(iVar10 + uVar9 * 4) != iVar5) goto LAB_0800faf0;
  FUN_0800d316(local_68);
  uVar9 = uVar9 + 1;
  param_4 = 0xffffffff;
  goto LAB_0800f944;
LAB_0800fb68:
  if (uVar9 == local_8c) {
LAB_0800fb6c:
    if ((1 < local_3c) && (iVar10 = FUN_08018262(&local_40,0x30,0), iVar10 != 0)) {
      if (iVar10 == -1) {
        iVar10 = local_3c - 1;
      }
      FUN_0800d5c8(&local_40,0,iVar10);
    }
    if ((local_80 != 0) && (*local_40 != '0')) {
      FUN_08017fc8(&local_40,local_40,0x2d);
    }
    if (local_54 != 0) {
      if (local_90 == 0) {
        local_88 = uVar11;
      }
      FUN_08017ede(&local_58,local_88 & 0xff);
      iVar10 = FUN_0801fe7c(*(undefined4 *)(iVar8 + 8),*(undefined4 *)(iVar8 + 0xc),&local_58);
      if (iVar10 == 0) {
        *puVar2 = *puVar2 | 4;
      }
    }
    if ((local_90 == 0) || (*(uint *)(iVar8 + 0x34) == uVar11)) {
      FUN_08018180(param_9,&local_40);
      goto LAB_0800fbee;
    }
  }
LAB_0800faf0:
  *puVar2 = *puVar2 | 4;
LAB_0800fbee:
  local_68 = param_3;
  local_64 = param_4;
  iVar8 = FUN_0800e0d6(&local_68,&param_5);
  if (iVar8 != 0) {
    *puVar2 = *puVar2 | 2;
  }
  *param_1 = local_68;
  param_1[1] = local_64;
  FUN_08006cec(&local_40);
  FUN_08006cec(&local_58);
  return param_1;
}

