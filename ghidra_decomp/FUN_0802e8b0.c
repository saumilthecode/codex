
char * FUN_0802e8b0(int param_1,undefined4 param_2,uint param_3,uint param_4,uint param_5,
                   char *param_6,undefined4 *param_7,uint *param_8,int *param_9)

{
  bool bVar1;
  bool bVar2;
  char cVar3;
  byte bVar4;
  uint uVar5;
  char *pcVar6;
  uint uVar7;
  char *pcVar8;
  int iVar9;
  undefined4 uVar10;
  uint uVar11;
  undefined4 uVar12;
  int iVar13;
  uint uVar14;
  undefined4 *puVar15;
  int iVar16;
  char *pcVar17;
  char *pcVar18;
  char *pcVar19;
  undefined4 uVar20;
  char *pcVar21;
  char *pcVar22;
  bool bVar23;
  undefined8 uVar24;
  undefined8 uVar25;
  undefined8 uVar26;
  uint local_98;
  undefined4 local_90;
  uint local_8c;
  char *local_84;
  char *local_80;
  char *local_7c;
  char *local_78;
  char *local_74;
  char *local_70;
  char *local_68;
  uint uStack_64;
  char *local_58;
  char *local_50;
  char *local_4c;
  int local_38;
  char *local_34;
  int local_30;
  int local_2c [2];
  
  uVar7 = param_5;
  iVar9 = *(int *)(param_1 + 0x38);
  if (iVar9 != 0) {
    uVar11 = *(uint *)(param_1 + 0x3c);
    *(uint *)(iVar9 + 4) = uVar11;
    *(int *)(iVar9 + 8) = 1 << (uVar11 & 0xff);
    FUN_08028fe8();
    *(undefined4 *)(param_1 + 0x38) = 0;
  }
  *param_8 = (uint)((int)param_4 < 0);
  local_8c = param_4;
  if ((int)param_4 < 0) {
    local_8c = param_4 & 0x7fffffff;
  }
  uVar11 = local_8c;
  if ((DAT_0802ebb0 & ~local_8c) == 0) {
    *param_7 = 9999;
    if ((local_8c & 0xfffff) == 0 && param_3 == 0) {
      if (param_9 == (int *)0x0) {
        return DAT_0802f8f0;
      }
      local_84 = DAT_0802ebc4;
      pcVar19 = DAT_0802ebc4 + 8;
    }
    else {
      if (param_9 == (int *)0x0) {
        return DAT_0802ebc8;
      }
      local_84 = DAT_0802f038;
      pcVar19 = DAT_0802f038 + 3;
    }
    *param_9 = (int)pcVar19;
    return local_84;
  }
  uVar24 = FUN_080066f8(param_3,local_8c,0,0);
  if ((int)uVar24 != 0) {
    *param_7 = 1;
    if (param_9 != (int *)0x0) {
      *param_9 = DAT_0802ebb4;
    }
    return DAT_0802ebb8;
  }
  local_7c = (char *)FUN_08029730(param_1,(int)((ulonglong)uVar24 >> 0x20),param_3,local_8c,local_2c
                                  ,&local_30);
  iVar9 = local_30;
  if (local_8c >> 0x14 == 0) {
    iVar16 = local_2c[0] + local_30;
    iVar13 = iVar16 + 0x432;
    if (iVar13 < 0x21) {
      uVar5 = param_3 << (0x20U - iVar13 & 0xff);
    }
    else {
      uVar5 = local_8c << (0x40U - iVar13 & 0xff) | param_3 >> (iVar16 + 0x412U & 0xff);
    }
    uVar24 = FUN_08006134(uVar5);
    iVar16 = iVar16 + -1;
    uVar14 = (int)((ulonglong)uVar24 >> 0x20) + 0xfe100000;
    bVar1 = true;
    uVar5 = (uint)uVar24;
  }
  else {
    iVar16 = (local_8c >> 0x14) - 0x3ff;
    uVar14 = local_8c & 0xfffff | 0x3ff00000;
    bVar1 = false;
    uVar5 = param_3;
  }
  uVar24 = FUN_08005eb8(uVar5,uVar14,0,DAT_0802ebbc);
  uVar24 = FUN_08006228((int)uVar24,(int)((ulonglong)uVar24 >> 0x20),DAT_0802eb98,DAT_0802eb9c);
  uVar24 = FUN_08005ebc((int)uVar24,(int)((ulonglong)uVar24 >> 0x20),DAT_0802eba0,DAT_0802eba4);
  uVar25 = FUN_08006154(iVar16);
  uVar25 = FUN_08006228((int)uVar25,(int)((ulonglong)uVar25 >> 0x20),DAT_0802eba8,DAT_0802ebac);
  uVar24 = FUN_08005ebc((int)uVar24,(int)((ulonglong)uVar24 >> 0x20),(int)uVar25,
                        (int)((ulonglong)uVar25 >> 0x20));
  uVar20 = (undefined4)((ulonglong)uVar24 >> 0x20);
  pcVar19 = (char *)uVar24;
  pcVar6 = (char *)FUN_08006b60();
  iVar13 = FUN_0800670c(pcVar19,uVar20,0,0);
  local_80 = pcVar6;
  if (iVar13 != 0) {
    uVar24 = FUN_08006154(pcVar6);
    iVar13 = FUN_080066f8((int)uVar24,(int)((ulonglong)uVar24 >> 0x20),pcVar19,uVar20);
    if (iVar13 == 0) {
      local_80 = pcVar6 + -1;
    }
  }
  pcVar21 = (char *)(iVar9 - iVar16);
  pcVar22 = pcVar21 + -1;
  if (local_80 < (char *)0x17) {
    puVar15 = (undefined4 *)(DAT_0802ebc0 + (int)local_80 * 8);
    iVar9 = FUN_0800670c(param_3,local_8c,*puVar15,puVar15[1]);
    if (iVar9 != 0) {
      local_80 = local_80 + -1;
      bVar2 = false;
      goto LAB_0802ebd4;
    }
    bVar2 = false;
    if ((int)pcVar21 < 1) {
      local_78 = (char *)(1 - (int)pcVar21);
      local_70 = local_80;
      pcVar22 = local_80;
    }
    else {
      local_70 = local_80;
      local_78 = (char *)0x0;
      pcVar22 = pcVar22 + (int)local_80;
    }
LAB_0802ea10:
    local_74 = (char *)0x0;
    local_80 = local_70;
  }
  else {
    bVar2 = true;
LAB_0802ebd4:
    if ((int)pcVar22 < 0) {
      local_78 = (char *)(1 - (int)pcVar21);
      pcVar22 = (char *)0x0;
    }
    else {
      local_78 = (char *)0x0;
    }
    if (-1 < (int)local_80) {
      pcVar22 = pcVar22 + (int)local_80;
      local_70 = local_80;
      goto LAB_0802ea10;
    }
    local_78 = local_78 + -(int)local_80;
    local_74 = (char *)-(int)local_80;
    local_70 = (char *)0x0;
  }
  pcVar8 = (char *)0x0;
  if (9 < param_5) {
    param_5 = 0;
switchD_0802ea32_default:
    pcVar17 = (char *)0x0;
    *(undefined4 *)(param_1 + 0x3c) = 0;
    local_84 = (char *)FUN_08028f6c(param_1,0);
    if (local_84 != (char *)0x0) {
      *(char **)(param_1 + 0x38) = local_84;
      if ((-1 < local_2c[0]) && ((int)local_80 < 0xf)) {
        puVar15 = (undefined4 *)(DAT_0802ebc0 + (int)local_80 * 8);
        local_90 = *puVar15;
        uVar20 = puVar15[1];
        FUN_0800647c(param_3,local_8c,local_90,uVar20);
        cVar3 = FUN_08006b60();
        uVar24 = FUN_08006154();
        uVar24 = FUN_08006228((int)uVar24,(int)((ulonglong)uVar24 >> 0x20),local_90,uVar20);
        uVar24 = FUN_08005eb8(param_3,local_8c,(int)uVar24,(int)((ulonglong)uVar24 >> 0x20));
        local_68 = local_84 + 1;
        *local_84 = cVar3 + '0';
        pcVar17 = (char *)0xffffffff;
        local_8c = uVar20;
        goto LAB_0802eb08;
      }
      pcVar17 = (char *)0xffffffff;
      param_6 = (char *)0x0;
      local_50 = (char *)0xffffffff;
      goto LAB_0802ec20;
    }
    goto LAB_0802f80a;
  }
  if (5 < (int)param_5) {
    param_5 = param_5 - 4;
  }
  pcVar17 = (char *)(uint)((int)uVar7 < 6);
  pcVar18 = local_78;
  switch(param_5) {
  case 2:
    local_58 = (char *)0x0;
    break;
  case 3:
    local_58 = (char *)0x0;
    goto LAB_0802edc4;
  case 4:
    local_58 = (char *)0x1;
    break;
  case 5:
    local_58 = (char *)0x1;
LAB_0802edc4:
    local_50 = param_6 + (int)local_80;
    pcVar8 = local_50 + 1;
    pcVar19 = pcVar8;
    if ((int)pcVar8 < 1) {
      pcVar19 = (char *)0x1;
    }
    goto LAB_0802edd8;
  default:
    goto switchD_0802ea32_default;
  }
  if ((int)param_6 < 1) {
    *(undefined4 *)(param_1 + 0x3c) = 0;
    local_84 = (char *)FUN_08028f6c(param_1);
    if (local_84 == (char *)0x0) goto LAB_0802f80a;
    *(char **)(param_1 + 0x38) = local_84;
    param_6 = pcVar17;
    local_50 = pcVar17;
    if (pcVar17 != (char *)0x0) goto LAB_0802ee12;
    if (-1 < local_2c[0]) {
      pcVar17 = (char *)0x1;
      local_50 = (char *)0x1;
      param_6 = (char *)0x1;
      goto LAB_0802f05c;
    }
    if (local_58 != (char *)0x0) {
      param_6 = local_58;
      local_50 = param_6;
      goto LAB_0802f324;
    }
    pcVar17 = (char *)0x1;
    local_50 = (char *)0x1;
    param_6 = (char *)0x1;
LAB_0802f2ee:
    pcVar21 = local_74;
    if (local_78 == (char *)0x0) {
      if (local_74 == (char *)0x0) {
        pcVar18 = (char *)0x0;
      }
      else {
LAB_0802f3fa:
        local_7c = (char *)FUN_08029360(param_1,local_7c,local_74);
        local_74 = (char *)0x0;
        pcVar18 = local_78;
        pcVar21 = (char *)0x0;
      }
    }
    else {
      if (pcVar22 != (char *)0x0) {
        pcVar19 = local_78;
        if ((int)pcVar22 <= (int)local_78) {
          pcVar19 = pcVar22;
        }
        pcVar22 = pcVar22 + -(int)pcVar19;
        pcVar18 = local_78 + -(int)pcVar19;
      }
      local_78 = pcVar18;
      if (local_74 != (char *)0x0) goto LAB_0802f3fa;
    }
LAB_0802ec66:
    local_98 = FUN_080291e4(param_1,1);
    if (local_70 == (char *)0x0) {
      if (((((int)param_5 < 2) && (param_3 == 0)) && ((local_8c & 0xfffff) == 0)) &&
         ((local_8c & 0x7ff00000) != 0)) {
        iVar9 = 1;
        pcVar18 = pcVar18 + 1;
        pcVar22 = pcVar22 + 1;
        local_70 = (char *)0x1;
      }
      else {
        iVar9 = 1;
      }
    }
    else {
      local_98 = FUN_08029360(param_1,local_98,local_70);
      if (((int)param_5 < 2) && (param_3 == 0)) {
        if ((local_8c & 0xfffff) == 0) {
          local_70 = (char *)(local_8c & 0x7ff00000);
          if (local_70 != (char *)0x0) {
            pcVar18 = pcVar18 + 1;
            pcVar22 = pcVar22 + 1;
            local_70 = (char *)0x1;
          }
        }
        else {
          local_70 = (char *)0x0;
        }
      }
      else {
        local_70 = (char *)0x0;
      }
      iVar9 = FUN_0802914c(*(undefined4 *)(local_98 + *(int *)(local_98 + 0x10) * 4 + 0x10));
      iVar9 = 0x20 - iVar9;
    }
    uVar7 = (uint)(pcVar22 + iVar9) & 0x1f;
    if (uVar7 == 0) {
      iVar9 = 0x1c;
LAB_0802f02a:
      local_78 = local_78 + iVar9;
      pcVar18 = pcVar18 + iVar9;
      pcVar22 = pcVar22 + iVar9;
    }
    else if ((int)(0x20 - uVar7) < 5) {
      if (0x20 - uVar7 != 4) {
        iVar9 = 0x3c - uVar7;
        goto LAB_0802f02a;
      }
    }
    else {
      iVar9 = 0x1c - uVar7;
      local_78 = local_78 + iVar9;
      pcVar18 = pcVar18 + iVar9;
      pcVar22 = pcVar22 + iVar9;
    }
    if (0 < (int)pcVar18) {
      local_7c = (char *)FUN_08029418(param_1,local_7c,pcVar18);
    }
    if (0 < (int)pcVar22) {
      local_98 = FUN_08029418(param_1,local_98,pcVar22);
    }
    if ((!bVar2) || (iVar9 = FUN_080294f4(local_7c,local_98), -1 < iVar9)) {
      local_50 = pcVar17;
      if (((int)pcVar17 < 1) && (pcVar19 = local_80, 2 < (int)param_5)) goto LAB_0802f244;
      if (local_74 == (char *)0x0) {
        local_80 = local_80 + 1;
        goto LAB_0802ece2;
      }
LAB_0802f0de:
      pcVar19 = pcVar21;
      if (0 < (int)local_78) {
        pcVar19 = (char *)FUN_08029418(param_1,pcVar21,local_78);
      }
      pcVar21 = pcVar19;
      if (local_70 != (char *)0x0) {
        iVar9 = FUN_08028f6c(param_1,*(undefined4 *)(pcVar19 + 4));
        if (iVar9 == 0) {
          FUN_08028754(DAT_0802f8ec,0x2ef,0,DAT_0802f8e8);
          return DAT_0802f8f0;
        }
        FUN_08028666(iVar9 + 0xc,pcVar19 + 0xc,(*(int *)(pcVar19 + 0x10) + 2) * 4);
        pcVar21 = (char *)FUN_08029418(param_1,iVar9,1);
      }
      pcVar17 = local_84;
      while( true ) {
        pcVar8 = (char *)FUN_0802e780(local_7c,local_98);
        iVar9 = FUN_080294f4(local_7c,pcVar19);
        iVar16 = FUN_0802952c(param_1,local_98,pcVar21);
        pcVar6 = pcVar8 + 0x30;
        if (*(int *)(iVar16 + 0xc) != 0) break;
        iVar13 = FUN_080294f4(local_7c);
        FUN_08028fe8(param_1,iVar16);
        if (iVar13 == 0) {
          if ((param_5 == 0) && ((param_3 & 1) == 0)) {
            if (pcVar6 == (char *)0x39) goto LAB_0802f7d4;
            if (0 < iVar9) goto LAB_0802f1e6;
            goto LAB_0802f1ea;
          }
          if (iVar9 < 0) goto LAB_0802f1ea;
        }
        else {
          pcVar22 = local_7c;
          if ((iVar9 < 0) || ((iVar9 == 0 && param_5 == 0) && (param_3 & 1) == 0))
          goto LAB_0802f818;
          if (0 < iVar13) goto LAB_0802f220;
        }
        pcVar22 = pcVar17 + 1;
        *pcVar17 = (char)pcVar6;
        if (pcVar17 == local_84 + -1 + (int)local_50) {
          local_80 = local_80 + 1;
          goto LAB_0802ed34;
        }
        local_7c = (char *)FUN_0802902c(param_1,local_7c,10,0);
        pcVar17 = pcVar22;
        if (pcVar19 == pcVar21) {
          pcVar19 = (char *)FUN_0802902c(param_1,pcVar19,10,0);
          pcVar21 = pcVar19;
        }
        else {
          pcVar19 = (char *)FUN_0802902c(param_1,pcVar19,10,0);
          pcVar21 = (char *)FUN_0802902c(param_1,pcVar21,10,0);
        }
      }
      FUN_08028fe8(param_1,iVar16);
      if ((iVar9 < 0) || ((param_3 & 1) == 0 && (iVar9 == 0 && param_5 == 0))) goto LAB_0802f1c6;
LAB_0802f220:
      if (pcVar6 == (char *)0x39) goto LAB_0802f7d4;
      local_68 = pcVar17 + 1;
      *pcVar17 = (char)pcVar6 + '\x01';
      local_80 = local_80 + 1;
      goto LAB_0802ed6a;
    }
    local_7c = (char *)FUN_0802902c(param_1,local_7c,10,0);
    pcVar19 = local_80 + -1;
    if (local_74 == (char *)0x0) {
      if (((int)local_50 < 1) && (2 < (int)param_5)) goto LAB_0802f244;
LAB_0802ece2:
      iVar9 = 1;
      pcVar19 = local_84;
      while( true ) {
        iVar16 = FUN_0802e780(local_7c,local_98);
        pcVar6 = (char *)(iVar16 + 0x30);
        *pcVar19 = (char)pcVar6;
        if ((int)local_50 <= iVar9) break;
        local_7c = (char *)FUN_0802902c(param_1,local_7c,10,0);
        iVar9 = iVar9 + 1;
        pcVar19 = pcVar19 + 1;
      }
      pcVar22 = local_50 + -1;
      if ((int)local_50 < 1) {
        pcVar22 = (char *)0x0;
      }
      pcVar22 = pcVar22 + (int)(local_84 + 1);
      pcVar19 = (char *)0x0;
LAB_0802ed34:
      local_7c = (char *)FUN_08029418(param_1,local_7c,1);
      iVar9 = FUN_080294f4(local_7c,local_98);
      pcVar8 = local_84;
      if ((iVar9 < 1) && ((iVar9 != 0 || (((uint)pcVar6 & 1) == 0)))) {
        do {
          local_68 = pcVar22;
          pcVar22 = local_68 + -1;
        } while (local_68[-1] == '0');
        goto LAB_0802ed6a;
      }
      goto LAB_0802ed56;
    }
    pcVar21 = (char *)FUN_0802902c(param_1,pcVar21,10,0);
    local_80 = pcVar19;
    if ((0 < (int)local_50) || ((int)param_5 < 3)) goto LAB_0802f0de;
LAB_0802f244:
    local_80 = pcVar19;
    if (local_50 == (char *)0x0) {
      local_98 = FUN_0802902c(param_1,local_98,5,0);
      iVar9 = FUN_080294f4(local_7c,local_98);
      if (iVar9 < 1) goto LAB_0802f56e;
      *local_84 = '1';
      FUN_08028fe8(param_1,local_98);
      local_80 = local_80 + 2;
      local_68 = local_84 + 1;
    }
    else {
LAB_0802f56e:
      FUN_08028fe8(param_1,local_98);
      local_80 = (char *)-(int)param_6;
      local_68 = local_84;
    }
    if (pcVar21 == (char *)0x0) goto LAB_0802eb72;
  }
  else {
    local_50 = param_6;
    pcVar19 = param_6;
    pcVar8 = param_6;
LAB_0802edd8:
    if ((int)pcVar19 < 0x18) {
      *(undefined4 *)(param_1 + 0x3c) = 0;
    }
    else {
      iVar16 = 4;
      iVar9 = 1;
      do {
        iVar13 = iVar9;
        iVar16 = iVar16 * 2;
        iVar9 = iVar13 + 1;
      } while ((char *)(iVar16 + 0x14) <= pcVar19);
      *(int *)(param_1 + 0x3c) = iVar13;
    }
    local_84 = (char *)FUN_08028f6c(param_1);
    if (local_84 != (char *)0x0) {
      *(char **)(param_1 + 0x38) = local_84;
      if ((pcVar8 < (char *)0xf) && (bVar23 = pcVar17 != (char *)0x0, pcVar17 = pcVar8, bVar23)) {
LAB_0802ee12:
        local_68 = (char *)param_3;
        if ((int)local_80 < 1) {
          if (local_80 == (char *)0x0) {
            iVar9 = 2;
            uStack_64 = local_8c;
          }
          else {
            puVar15 = (undefined4 *)(DAT_0802f760 + (-(int)local_80 & 0xfU) * 8);
            uVar24 = FUN_08006228(param_3,local_8c,*puVar15,puVar15[1]);
            uStack_64 = (uint)((ulonglong)uVar24 >> 0x20);
            local_68 = (char *)uVar24;
            iVar16 = -(int)local_80 >> 4;
            if (iVar16 == 0) {
              iVar9 = 2;
            }
            else {
              iVar9 = 2;
              puVar15 = DAT_0802f764;
              do {
                while( true ) {
                  uStack_64 = (uint)((ulonglong)uVar24 >> 0x20);
                  local_68 = (char *)uVar24;
                  iVar13 = iVar16 << 0x1f;
                  iVar16 = iVar16 >> 1;
                  if (iVar13 < 0) break;
                  puVar15 = puVar15 + 2;
                }
                uVar24 = FUN_08006228(local_68,uStack_64,*puVar15,puVar15[1]);
                uStack_64 = (uint)((ulonglong)uVar24 >> 0x20);
                local_68 = (char *)uVar24;
                iVar9 = iVar9 + 1;
                puVar15 = puVar15 + 2;
              } while (iVar16 != 0);
            }
          }
        }
        else {
          uVar24 = *(undefined8 *)(DAT_0802f03c + ((uint)local_80 & 0xf) * 8);
          uVar7 = (int)local_80 >> 4;
          if ((int)local_80 << 0x17 < 0) {
            uVar25 = FUN_0800647c(param_3,local_8c,DAT_0802f040[8],DAT_0802f040[9]);
            uStack_64 = (uint)((ulonglong)uVar25 >> 0x20);
            local_68 = (char *)uVar25;
            uVar7 = uVar7 & 0xf;
            iVar9 = 3;
            puVar15 = DAT_0802f040;
          }
          else {
            iVar9 = 2;
            uStack_64 = local_8c;
            puVar15 = DAT_0802f040;
          }
          while( true ) {
            uVar20 = (undefined4)((ulonglong)uVar24 >> 0x20);
            if (uVar7 == 0) break;
            while (iVar16 = uVar7 << 0x1f, uVar7 = (int)uVar7 >> 1, -1 < iVar16) {
              puVar15 = puVar15 + 2;
            }
            uVar24 = FUN_08006228((int)uVar24,uVar20,*puVar15,puVar15[1]);
            iVar9 = iVar9 + 1;
            puVar15 = puVar15 + 2;
          }
          uVar24 = FUN_0800647c(local_68,uStack_64,(int)uVar24,uVar20);
          uStack_64 = (uint)((ulonglong)uVar24 >> 0x20);
          local_68 = (char *)uVar24;
        }
        uVar24 = CONCAT44(uStack_64,local_68);
        pcVar8 = pcVar17;
        if ((!bVar2) || (iVar16 = FUN_0800670c(local_68,uStack_64,0,DAT_0802f044), iVar16 == 0)) {
          uVar25 = FUN_08006154(iVar9);
          uVar25 = FUN_08006228((int)uVar25,(int)((ulonglong)uVar25 >> 0x20),local_68,uStack_64);
          uVar25 = FUN_08005ebc((int)uVar25,(int)((ulonglong)uVar25 >> 0x20),0,DAT_0802f048);
          uVar20 = (undefined4)uVar25;
          iVar9 = (int)((ulonglong)uVar25 >> 0x20) + -0x3400000;
          if (pcVar17 == (char *)0x0) goto LAB_0802f484;
          local_34 = local_80;
          local_4c = pcVar17;
LAB_0802eec6:
          iVar16 = DAT_0802f03c;
          uStack_64 = (uint)((ulonglong)uVar24 >> 0x20);
          local_68 = (char *)uVar24;
          local_38 = DAT_0802f03c;
          iVar13 = DAT_0802f03c + (int)local_4c * 8;
          uVar10 = *(undefined4 *)(iVar13 + -8);
          uVar12 = *(undefined4 *)(iVar13 + -4);
          cVar3 = FUN_08006b60(local_68,uStack_64);
          uVar24 = FUN_08006154();
          uVar24 = FUN_08005eb8(local_68,uStack_64,(int)uVar24,(int)((ulonglong)uVar24 >> 0x20));
          local_68 = local_84 + 1;
          pcVar6 = local_84;
          pcVar19 = local_68;
          if (local_58 != (char *)0x0) {
            uVar25 = FUN_0800647c(0,DAT_0802f04c,uVar10,uVar12);
            uVar25 = FUN_08005eb8((int)uVar25,(int)((ulonglong)uVar25 >> 0x20),uVar20,iVar9);
            *local_84 = cVar3 + '0';
            iVar9 = FUN_08006748((int)uVar25,(int)((ulonglong)uVar25 >> 0x20),(int)uVar24,
                                 (int)((ulonglong)uVar24 >> 0x20));
            if (iVar9 == 0) {
              iVar9 = 0;
              do {
                uVar20 = (undefined4)((ulonglong)uVar25 >> 0x20);
                uVar10 = (undefined4)((ulonglong)uVar24 >> 0x20);
                uVar26 = FUN_08005eb8(0,DAT_0802f044,(int)uVar24,uVar10);
                iVar16 = FUN_0800670c((int)uVar26,(int)((ulonglong)uVar26 >> 0x20),(int)uVar25,
                                      uVar20);
                if (iVar16 != 0) {
                  local_80 = local_34 + 1;
                  goto LAB_0802efe2;
                }
                iVar9 = iVar9 + 1;
                if ((int)local_4c <= iVar9) {
                  if ((local_2c[0] < 0) || (0xe < (int)local_80)) goto LAB_0802f31c;
                  goto LAB_0802f068;
                }
                uVar25 = FUN_08006228((int)uVar25,uVar20,0,DAT_0802f050);
                uVar24 = FUN_08006228((int)uVar24,uVar10,0,DAT_0802f050);
                cVar3 = FUN_08006b60();
                uVar26 = FUN_08006154();
                uVar24 = FUN_08005eb8((int)uVar24,(int)((ulonglong)uVar24 >> 0x20),(int)uVar26,
                                      (int)((ulonglong)uVar26 >> 0x20));
                local_68 = pcVar19 + 1;
                *pcVar19 = cVar3 + '0';
                iVar16 = FUN_0800670c((int)uVar24,(int)((ulonglong)uVar24 >> 0x20),(int)uVar25,
                                      (int)((ulonglong)uVar25 >> 0x20));
                pcVar19 = local_68;
              } while (iVar16 == 0);
            }
            local_80 = local_34 + 1;
            goto LAB_0802eb72;
          }
          uVar25 = FUN_08006228(uVar10,uVar12,uVar20,iVar9);
          uVar20 = (undefined4)((ulonglong)uVar25 >> 0x20);
          *local_84 = cVar3 + '0';
          if (local_4c != (char *)0x1) {
            do {
              uVar24 = FUN_08006228((int)uVar24,(int)((ulonglong)uVar24 >> 0x20),0,DAT_0802f768);
              cVar3 = FUN_08006b60();
              uVar26 = FUN_08006154();
              uVar24 = FUN_08005eb8((int)uVar24,(int)((ulonglong)uVar24 >> 0x20),(int)uVar26,
                                    (int)((ulonglong)uVar26 >> 0x20));
              pcVar21 = pcVar19 + 1;
              *pcVar19 = cVar3 + '0';
              pcVar19 = pcVar21;
            } while (pcVar21 != local_84 + (int)local_4c);
            pcVar19 = local_84 + (int)local_4c;
          }
          uVar10 = (undefined4)((ulonglong)uVar24 >> 0x20);
          uVar26 = FUN_08005ebc((int)uVar25,uVar20,0,DAT_0802f76c);
          iVar9 = FUN_0800670c((int)uVar26,(int)((ulonglong)uVar26 >> 0x20),(int)uVar24,uVar10);
          if (iVar9 == 0) {
            uVar25 = FUN_08005eb8(0,DAT_0802f76c,(int)uVar25,uVar20);
            iVar9 = FUN_08006748((int)uVar25,(int)((ulonglong)uVar25 >> 0x20),(int)uVar24,uVar10);
            if (iVar9 != 0) {
              do {
                local_68 = pcVar19;
                pcVar19 = local_68 + -1;
              } while (local_68[-1] == '0');
              local_80 = local_34 + 1;
              goto LAB_0802eb72;
            }
            if ((local_2c[0] < 0) || (0xe < (int)local_80)) goto LAB_0802f2ee;
            puVar15 = (undefined4 *)(iVar16 + (int)local_80 * 8);
            local_90 = *puVar15;
            local_8c = puVar15[1];
            goto LAB_0802f628;
          }
          local_80 = local_34 + 1;
LAB_0802efe2:
          do {
            local_68 = pcVar19;
            pcVar19 = local_68 + -1;
            if (*pcVar19 != '9') {
              cVar3 = *pcVar19 + '\x01';
              goto LAB_0802eff0;
            }
          } while (pcVar19 != pcVar6);
          local_80 = local_80 + 1;
          cVar3 = '1';
LAB_0802eff0:
          *pcVar19 = cVar3;
          goto LAB_0802eb72;
        }
        if (pcVar17 != (char *)0x0) {
          if (0 < (int)local_50) {
            local_34 = local_80 + -1;
            uVar24 = FUN_08006228(local_68,uStack_64,0,DAT_0802f8e0);
            uVar25 = FUN_08006154(iVar9 + 1);
            uVar25 = FUN_08006228((int)uVar25,(int)((ulonglong)uVar25 >> 0x20),(int)uVar24,
                                  (int)((ulonglong)uVar24 >> 0x20));
            uVar25 = FUN_08005ebc((int)uVar25,(int)((ulonglong)uVar25 >> 0x20),0,DAT_0802f8e4);
            uVar20 = (undefined4)uVar25;
            local_4c = local_50;
            iVar9 = (int)((ulonglong)uVar25 >> 0x20) + -0x3400000;
            goto LAB_0802eec6;
          }
          goto LAB_0802f054;
        }
        uVar24 = FUN_08006154(iVar9);
        uVar24 = FUN_08006228((int)uVar24,(int)((ulonglong)uVar24 >> 0x20),local_68,uStack_64);
        uVar24 = FUN_08005ebc((int)uVar24,(int)((ulonglong)uVar24 >> 0x20),0,DAT_0802f758);
        uVar20 = (undefined4)uVar24;
        iVar9 = (int)((ulonglong)uVar24 >> 0x20) + -0x3400000;
LAB_0802f484:
        uVar24 = FUN_08005eb8(local_68,uStack_64,0,DAT_0802f75c);
        uVar10 = (undefined4)((ulonglong)uVar24 >> 0x20);
        iVar16 = FUN_08006748((int)uVar24,uVar10,uVar20,iVar9);
        if (iVar16 != 0) {
          local_68 = local_84 + 1;
          *local_84 = '1';
          FUN_08028fe8(param_1,0);
          local_80 = local_80 + 2;
          goto LAB_0802eb72;
        }
        iVar9 = FUN_0800670c((int)uVar24,uVar10,uVar20,iVar9 + -0x80000000);
        if (iVar9 == 0) goto LAB_0802f054;
LAB_0802f4b8:
        FUN_08028fe8(param_1,0);
        local_80 = (char *)-(int)param_6;
        local_68 = local_84;
        goto LAB_0802eb72;
      }
LAB_0802f054:
      pcVar17 = pcVar8;
      if (-1 < local_2c[0]) {
LAB_0802f05c:
        if ((int)local_80 < 0xf) {
          local_38 = DAT_0802f300;
LAB_0802f068:
          puVar15 = (undefined4 *)(local_38 + (int)local_80 * 8);
          local_90 = *puVar15;
          uVar20 = puVar15[1];
          if ((-1 < (int)param_6) || (0 < (int)pcVar17)) {
            local_68 = local_84 + 1;
            local_8c = uVar20;
LAB_0802f628:
            FUN_0800647c(param_3,uVar11,local_90,local_8c);
            bVar4 = FUN_08006b60();
            uVar24 = FUN_08006154();
            uVar24 = FUN_08006228((int)uVar24,(int)((ulonglong)uVar24 >> 0x20),local_90,local_8c);
            uVar24 = FUN_08005eb8(param_3,uVar11,(int)uVar24,(int)((ulonglong)uVar24 >> 0x20));
            *local_84 = bVar4 + 0x30;
            if (pcVar17 != (char *)0x1) {
LAB_0802eb08:
              pcVar6 = (char *)0x1;
              pcVar19 = local_68;
              do {
                uVar24 = FUN_08006228((int)uVar24,(int)((ulonglong)uVar24 >> 0x20),0,DAT_0802ebcc);
                uVar10 = (undefined4)((ulonglong)uVar24 >> 0x20);
                uVar20 = (undefined4)uVar24;
                iVar9 = FUN_080066f8(uVar20,uVar10,0,0);
                if (iVar9 != 0) {
                  local_80 = local_80 + 1;
                  local_68 = pcVar19;
                  goto LAB_0802eb72;
                }
                FUN_0800647c(uVar20,uVar10,local_90,local_8c);
                bVar4 = FUN_08006b60();
                uVar24 = FUN_08006154();
                uVar24 = FUN_08006228((int)uVar24,(int)((ulonglong)uVar24 >> 0x20),local_90,local_8c
                                     );
                pcVar6 = pcVar6 + 1;
                uVar24 = FUN_08005eb8(uVar20,uVar10,(int)uVar24,(int)((ulonglong)uVar24 >> 0x20));
                local_68 = pcVar19 + 1;
                *pcVar19 = bVar4 + 0x30;
                pcVar19 = local_68;
              } while (pcVar6 != pcVar17);
            }
            uVar20 = (undefined4)((ulonglong)uVar24 >> 0x20);
            uVar24 = FUN_08005ebc((int)uVar24,uVar20,(int)uVar24,uVar20);
            uVar20 = (undefined4)((ulonglong)uVar24 >> 0x20);
            local_80 = local_80 + 1;
            iVar9 = FUN_08006748((int)uVar24,uVar20,local_90,local_8c);
            pcVar6 = local_84;
            pcVar19 = local_68;
            if ((iVar9 == 0) &&
               ((iVar9 = FUN_080066f8((int)uVar24,uVar20,local_90,local_8c), iVar9 == 0 ||
                ((bVar4 & 1) == 0)))) goto LAB_0802eb72;
            goto LAB_0802efe2;
          }
          if (pcVar17 == (char *)0x0) {
            uVar24 = FUN_08006228(local_90,uVar20,0,DAT_0802f304);
            iVar9 = FUN_08006720(param_3,local_8c,(int)uVar24,(int)((ulonglong)uVar24 >> 0x20));
            if (iVar9 == 0) {
              *local_84 = '1';
              FUN_08028fe8(param_1,0);
              local_80 = local_80 + 2;
              local_68 = local_84 + 1;
              goto LAB_0802eb72;
            }
          }
          goto LAB_0802f4b8;
        }
      }
      if (local_58 == (char *)0x0) goto LAB_0802f2ee;
LAB_0802f31c:
      local_58 = pcVar17;
      if ((int)param_5 < 2) {
LAB_0802ec20:
        pcVar19 = local_74;
        if (bVar1) {
          local_58 = (char *)(local_2c[0] + 0x433);
        }
        else {
          local_58 = (char *)(0x36 - local_30);
        }
LAB_0802ec30:
        pcVar18 = local_78 + (int)local_58;
        pcVar22 = pcVar22 + (int)local_58;
        pcVar21 = (char *)FUN_080291e4(param_1,1);
        local_58 = pcVar17;
        if (local_78 != (char *)0x0) {
LAB_0802f350:
          pcVar17 = local_58;
          if (0 < (int)pcVar22) {
            pcVar6 = local_78;
            if ((int)pcVar22 <= (int)local_78) {
              pcVar6 = pcVar22;
            }
            local_78 = local_78 + -(int)pcVar6;
            pcVar18 = pcVar18 + -(int)pcVar6;
            pcVar22 = pcVar22 + -(int)pcVar6;
          }
        }
        if (local_74 == (char *)0x0) {
LAB_0802f442:
          local_74 = (char *)0x1;
          goto LAB_0802ec66;
        }
        if (pcVar19 != (char *)0x0) {
          pcVar21 = (char *)FUN_08029360(param_1,pcVar21,pcVar19);
          pcVar6 = (char *)FUN_08029210(param_1,pcVar21,local_7c);
          FUN_08028fe8(param_1,local_7c);
          local_74 = local_74 + -(int)pcVar19;
          local_7c = pcVar6;
          if (local_74 == (char *)0x0) goto LAB_0802f442;
        }
      }
      else {
LAB_0802f324:
        pcVar19 = local_58 + -1;
        pcVar17 = local_58;
        if ((int)pcVar19 <= (int)local_74) {
          pcVar19 = local_74 + -(int)pcVar19;
          if (-1 < (int)local_58) goto LAB_0802ec30;
          pcVar21 = (char *)FUN_080291e4(param_1,1);
          local_78 = local_78 + -(int)local_58;
          goto LAB_0802f350;
        }
        local_70 = local_70 + ((int)pcVar19 - (int)local_74);
        pcVar21 = (char *)FUN_080291e4(param_1,1);
        pcVar22 = pcVar22 + (int)local_58;
        pcVar18 = local_78 + (int)local_58;
        local_74 = pcVar19;
        if (local_78 != (char *)0x0) {
          pcVar6 = local_78;
          if ((int)pcVar22 <= (int)local_78) {
            pcVar6 = pcVar22;
          }
          local_78 = local_78 + -(int)pcVar6;
          pcVar18 = pcVar18 + -(int)pcVar6;
          pcVar22 = pcVar22 + -(int)pcVar6;
        }
      }
      local_7c = (char *)FUN_08029360(param_1,local_7c,local_74);
      local_74 = (char *)0x1;
      goto LAB_0802ec66;
    }
LAB_0802f80a:
    iVar13 = DAT_0802f8e8;
    FUN_08028754(DAT_0802f8ec,0x1af,0);
    local_98 = param_3;
LAB_0802f818:
    local_7c = pcVar22;
    if (0 < iVar13) {
LAB_0802f1c6:
      local_7c = (char *)FUN_08029418(param_1,local_7c,1);
      iVar9 = FUN_080294f4(local_7c,local_98);
      if ((0 < iVar9) || ((iVar9 == 0 && (((uint)pcVar6 & 1) != 0)))) {
        if (pcVar6 == (char *)0x39) {
LAB_0802f7d4:
          *pcVar17 = '9';
          local_80 = local_80 + 1;
          pcVar8 = local_84;
          pcVar22 = pcVar17 + 1;
LAB_0802ed56:
          do {
            local_68 = pcVar22;
            pcVar22 = local_68 + -1;
            if (local_68[-1] != '9') {
              *pcVar22 = local_68[-1] + '\x01';
              goto LAB_0802ed6a;
            }
          } while (pcVar22 != pcVar8);
          local_80 = local_80 + 1;
          *local_84 = '1';
          goto LAB_0802ed6a;
        }
LAB_0802f1e6:
        pcVar6 = pcVar8 + 0x31;
      }
    }
LAB_0802f1ea:
    local_68 = pcVar17 + 1;
    *pcVar17 = (char)pcVar6;
    local_80 = local_80 + 1;
LAB_0802ed6a:
    FUN_08028fe8(param_1,local_98);
    if (pcVar21 == (char *)0x0) goto LAB_0802eb72;
    if ((pcVar19 != (char *)0x0) && (pcVar19 != pcVar21)) {
      FUN_08028fe8(param_1,pcVar19);
    }
  }
  FUN_08028fe8(param_1,pcVar21);
LAB_0802eb72:
  FUN_08028fe8(param_1,local_7c);
  *local_68 = '\0';
  *param_7 = local_80;
  if (param_9 == (int *)0x0) {
    return local_84;
  }
  *param_9 = (int)local_68;
  return local_84;
}

