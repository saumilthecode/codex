
int FUN_0801f1d2(int param_1,int param_2,undefined1 param_3,undefined4 param_4,int *param_5,
                undefined4 param_6,int *param_7,int *param_8)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  byte bVar6;
  uint uVar7;
  byte bVar8;
  uint uVar9;
  undefined1 uVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  bool bVar14;
  bool bVar15;
  undefined4 uVar16;
  int *piVar17;
  int *piVar18;
  uint local_4c;
  int local_48;
  int local_34;
  undefined4 local_30;
  uint local_2c;
  
  iVar3 = param_8[2] << 0x1b;
  bVar14 = iVar3 < 0;
  if (bVar14) {
    iVar3 = *(int *)(param_1 + 8);
  }
  if (bVar14) {
    param_8[2] = iVar3;
  }
  if ((param_5 == param_7) && (iVar3 = FUN_08008590(param_1,param_6), iVar3 != 0)) {
    *(undefined1 *)((int)param_8 + 5) = param_3;
  }
  else {
    iVar3 = FUN_08008590(param_1,param_4);
    if (iVar3 == 0) {
      if (param_2 < 0) {
        local_4c = 0;
      }
      else {
        local_4c = (int)param_7 - param_2;
      }
      local_48 = 2;
      bVar14 = true;
      iVar11 = 0;
      bVar1 = false;
      iVar3 = 0;
      do {
        iVar12 = *(int *)(param_1 + 0xc);
        iVar13 = param_1 + iVar12 * 8;
        for (; iVar12 != 0; iVar12 = iVar12 + -1) {
          local_34 = 0;
          local_30 = 0;
          iVar4 = *(int *)(iVar13 + 0xc);
          local_2c = param_8[2];
          bVar15 = iVar4 << 0x1f < 0;
          if (bVar15) {
            iVar3 = *param_5;
          }
          iVar2 = iVar4 >> 8;
          if (bVar15) {
            iVar2 = *(int *)(iVar3 + iVar2);
          }
          if ((local_4c == 0) || (local_4c < (uint)(iVar2 + (int)param_5) != bVar14)) {
            if ((iVar4 << 0x1e < 0) || ((param_2 != -2 || ((local_2c & 3) != 0)))) {
              piVar18 = &local_34;
              uVar16 = param_6;
              piVar17 = param_7;
              iVar3 = (**(code **)(**(int **)(iVar13 + 8) + 0x1c))(*(int **)(iVar13 + 8),param_2);
              uVar7 = (uint)local_30._2_1_;
              bVar8 = *(byte *)((int)param_8 + 5) | local_30._1_1_;
              uVar5 = (uint)bVar8;
              *(byte *)((int)param_8 + 5) = bVar8;
              if ((uVar7 == 6) || (uVar7 == 2)) {
                *param_8 = local_34;
                *(byte *)(param_8 + 1) = (byte)local_30;
                *(byte *)((int)param_8 + 6) = local_30._2_1_;
                return iVar3;
              }
              iVar4 = *param_8;
              if (iVar11 == 0) {
                if (iVar4 != 0) goto LAB_0801f348;
                *param_8 = local_34;
                *(byte *)(param_8 + 1) = (byte)local_30;
                iVar11 = iVar3;
                if (((local_34 != 0) && (uVar5 != 0)) && (-1 < *(int *)(param_1 + 8) << 0x1f)) {
                  return iVar3;
                }
              }
              else if (iVar4 == 0) {
                if (local_34 == 0) goto LAB_0801f332;
LAB_0801f360:
                bVar8 = *(byte *)((int)param_8 + 6);
                uVar9 = (uint)bVar8;
                if ((uVar5 < 4) || (((int)(uVar5 << 0x1f) < 0 && (param_8[2] << 0x1e < 0)))) {
                  if (uVar9 == 0) {
                    if ((3 < uVar7) &&
                       ((-1 < (int)(uVar7 << 0x1f) || (-1 < *(int *)(param_1 + 8) << 0x1e)))) {
                      uVar9 = 1;
                      goto LAB_0801f3ce;
                    }
                    uVar9 = FUN_0801f1a6(param_4,param_2,iVar4,param_6,param_7,uVar16,piVar17,
                                         piVar18);
                  }
                  if (uVar7 == 0) {
                    if ((uVar9 < 4) ||
                       (((int)(uVar9 << 0x1f) < 0 && (*(int *)(param_1 + 8) << 0x1e < 0)))) {
                      uVar7 = FUN_0801f1a6(param_4,param_2,local_34,param_6,param_7,uVar16,piVar17,
                                           piVar18);
                    }
                    else {
                      uVar7 = 1;
                    }
                  }
                }
                else {
                  if (uVar9 == 0) {
                    bVar8 = 1;
                  }
                  bVar6 = local_30._2_1_;
                  if (uVar7 == 0) {
                    bVar6 = 1;
                  }
                  uVar9 = (uint)bVar8;
                  uVar7 = (uint)bVar6;
                }
LAB_0801f3ce:
                uVar10 = (undefined1)(uVar7 ^ uVar9);
                if (((uVar7 ^ uVar9) & 0xff) < 4) {
                  *param_8 = 0;
                  if (3 < (uVar7 & uVar9 & 0xff)) {
                    *(undefined1 *)((int)param_8 + 6) = 2;
                    return 1;
                  }
                  iVar11 = 1;
                  *(undefined1 *)((int)param_8 + 6) = 1;
                }
                else {
                  if (3 < uVar7) {
                    *param_8 = local_34;
                    uVar10 = (undefined1)local_30;
                    uVar9 = uVar7;
                  }
                  if (3 < uVar7) {
                    *(undefined1 *)(param_8 + 1) = uVar10;
                    iVar11 = 0;
                  }
                  *(char *)((int)param_8 + 6) = (char)uVar9;
                  if (((int)(uVar9 << 0x1e) < 0) || ((uVar9 & 1) == 0)) {
                    return 0;
                  }
                }
              }
              else {
LAB_0801f348:
                if (local_34 == iVar4) {
                  *(byte *)(param_8 + 1) = *(byte *)(param_8 + 1) | (byte)local_30;
                }
                else if ((local_34 != 0) || (iVar3 != 0)) goto LAB_0801f360;
              }
LAB_0801f332:
              if (*(char *)((int)param_8 + 5) == '\x04') {
                return iVar11;
              }
            }
          }
          else {
            bVar1 = true;
          }
          iVar13 = iVar13 + -8;
          iVar3 = iVar11;
        }
        if (!bVar1) {
          return iVar11;
        }
        if (local_48 == 1) {
          return iVar11;
        }
        local_48 = 1;
        bVar14 = false;
      } while( true );
    }
    *param_8 = (int)param_5;
    *(undefined1 *)(param_8 + 1) = param_3;
    if (param_2 < 0) {
      if (param_2 == -2) {
        *(undefined1 *)((int)param_8 + 6) = 1;
      }
    }
    else {
      param_5 = (int *)(param_2 + (int)param_5);
      bVar14 = param_7 != param_5;
      if (bVar14) {
        param_5 = (int *)0x1;
      }
      uVar10 = SUB41(param_5,0);
      if (!bVar14) {
        uVar10 = 6;
      }
      *(undefined1 *)((int)param_8 + 6) = uVar10;
    }
  }
  return 0;
}

