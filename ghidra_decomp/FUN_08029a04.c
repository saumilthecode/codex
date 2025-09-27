
uint FUN_08029a04(byte *param_1,undefined4 *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  byte *pbVar3;
  byte *pbVar4;
  int iVar5;
  byte bVar6;
  uint uVar7;
  uint uVar8;
  
  pbVar4 = param_1;
  do {
    pbVar3 = pbVar4;
    pbVar4 = pbVar3 + 1;
    uVar2 = (uint)*pbVar3;
    bVar6 = *(byte *)(DAT_080299fc + uVar2) & 8;
  } while ((*(byte *)(DAT_080299fc + uVar2) & 8) != 0);
  if (uVar2 == 0x2d) {
    uVar2 = (uint)*pbVar4;
    bVar6 = 1;
    pbVar4 = pbVar3 + 2;
  }
  else if (uVar2 == 0x2b) {
    uVar2 = (uint)*pbVar4;
    pbVar4 = pbVar3 + 2;
  }
  if ((param_3 & 0xffffffef) == 0) {
    if ((uVar2 == 0x30) && ((*pbVar4 & 0xdf) == 0x58)) {
      uVar2 = (uint)pbVar4[1];
      pbVar4 = pbVar4 + 2;
    }
    else if (param_3 == 0) {
      if (uVar2 == 0x30) {
        param_3 = 8;
      }
      else {
        param_3 = 10;
      }
      goto LAB_08029978;
    }
    param_3 = 0x10;
  }
LAB_08029978:
  iVar5 = 0;
  uVar7 = 0xffffffff / param_3;
  uVar1 = 0;
  do {
    uVar8 = uVar2 - 0x30;
    if (9 < uVar8) {
      if (uVar2 - 0x41 < 0x1a) {
        uVar8 = uVar2 - 0x37;
      }
      else {
        if (0x19 < uVar2 - 0x61) break;
        uVar8 = uVar2 - 0x57;
      }
    }
    if ((int)param_3 <= (int)uVar8) break;
    if (iVar5 != -1) {
      if ((uVar7 < uVar1) || ((uVar7 == uVar1 && ((int)~(param_3 * uVar7) < (int)uVar8)))) {
        iVar5 = -1;
      }
      else {
        uVar1 = uVar1 * param_3 + uVar8;
        iVar5 = 1;
      }
    }
    uVar2 = (uint)*pbVar4;
    pbVar4 = pbVar4 + 1;
  } while( true );
  if (iVar5 == -1) {
    *(undefined4 *)*DAT_08029a14 = 0x22;
    uVar1 = 0xffffffff;
    if (param_2 == (undefined4 *)0x0) {
      return 0xffffffff;
    }
  }
  else {
    if (bVar6 != 0) {
      uVar1 = -uVar1;
    }
    if (param_2 == (undefined4 *)0x0) {
      return uVar1;
    }
    if (iVar5 == 0) goto LAB_080299f8;
  }
  param_1 = pbVar4 + -1;
LAB_080299f8:
  *param_2 = param_1;
  return uVar1;
}

