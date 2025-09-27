
undefined4 FUN_08000dbc(undefined4 *param_1,int param_2,uint param_3)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint *puVar7;
  uint uVar8;
  uint uVar9;
  
  iVar1 = FUN_0800061c();
  if (*(char *)((int)param_1 + 0x35) == '\x02') {
    if (*(int *)*param_1 << 0x17 < 0) {
      param_1[0x15] = 0x100;
    }
    else {
      uVar4 = param_1[0x17];
      if (param_2 == 0) {
        uVar8 = 0x20 << (uVar4 & 0xff);
      }
      else {
        uVar8 = 0x10 << (uVar4 & 0xff);
      }
      puVar7 = (uint *)param_1[0x16];
      if ((uVar8 & *puVar7) == 0) {
        if (param_3 == 0xffffffff) {
          uVar6 = 8 << (uVar4 & 0xff);
          uVar5 = 1 << (uVar4 & 0xff);
          uVar3 = 4 << (uVar4 & 0xff);
          do {
            if ((int)(param_1[0x15] << 0x1f) < 0) break;
            uVar9 = *puVar7;
            if ((uVar6 & uVar9) != 0) {
              param_1[0x15] = param_1[0x15] | 1;
              puVar7[2] = uVar6;
            }
            if ((uVar9 & uVar5) != 0) {
              param_1[0x15] = param_1[0x15] | 2;
              puVar7[2] = uVar5;
            }
            if ((uVar9 & uVar3) != 0) {
              param_1[0x15] = param_1[0x15] | 4;
              puVar7[2] = uVar3;
            }
          } while ((uVar9 & uVar8) == 0);
        }
        else if (param_3 == 0) {
          if (-1 < (int)(param_1[0x15] << 0x1f)) {
LAB_08000eb8:
            param_1[0x15] = 0x20;
            *(undefined1 *)(param_1 + 0xd) = 0;
            *(undefined1 *)((int)param_1 + 0x35) = 1;
            return 3;
          }
        }
        else {
          do {
            if ((int)(param_1[0x15] << 0x1f) < 0) break;
            iVar2 = FUN_0800061c();
            if (param_3 < (uint)(iVar2 - iVar1)) goto LAB_08000eb8;
            uVar4 = param_1[0x17];
            uVar6 = *puVar7;
            uVar9 = 8 << (uVar4 & 0xff);
            uVar3 = 1 << (uVar4 & 0xff);
            uVar5 = 4 << (uVar4 & 0xff);
            if ((uVar6 & uVar9) != 0) {
              param_1[0x15] = param_1[0x15] | 1;
              puVar7[2] = uVar9;
            }
            if ((uVar6 & uVar3) != 0) {
              param_1[0x15] = param_1[0x15] | 2;
              puVar7[2] = uVar3;
            }
            if ((uVar6 & uVar5) != 0) {
              param_1[0x15] = param_1[0x15] | 4;
              puVar7[2] = uVar5;
            }
          } while ((uVar8 & uVar6) == 0);
        }
      }
      if ((param_1[0x15] == 0) || (-1 < (int)(param_1[0x15] << 0x1f))) {
        if (param_2 == 0) {
          puVar7[2] = 0x30 << (uVar4 & 0xff);
          *(undefined1 *)((int)param_1 + 0x35) = 1;
          *(undefined1 *)(param_1 + 0xd) = 0;
        }
        else {
          puVar7[2] = 0x10 << (uVar4 & 0xff);
        }
        return 0;
      }
      FUN_08000d04(param_1);
      puVar7[2] = 0x30 << (param_1[0x17] & 0xff);
      *(undefined1 *)((int)param_1 + 0x35) = 1;
      *(undefined1 *)(param_1 + 0xd) = 0;
    }
  }
  else {
    param_1[0x15] = 0x80;
    *(undefined1 *)(param_1 + 0xd) = 0;
  }
  return 1;
}

