
/* WARNING: Removing unreachable block (ram,0x0802b632) */

undefined8 FUN_0802b3ac(uint param_1,uint param_2,uint param_3,uint param_4,uint *param_5)

{
  ulonglong uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  bool bVar12;
  
  if (param_4 != 0) {
    if (param_2 < param_4) {
      if (param_5 != (uint *)0x0) {
        *param_5 = param_1;
        param_5[1] = param_2;
      }
      uVar3 = 0;
      uVar2 = uVar3;
    }
    else {
      iVar4 = LZCOUNT(param_4);
      if (iVar4 == 0) {
        if ((param_4 < param_2) || (param_3 <= param_1)) {
          bVar12 = param_1 < param_3;
          param_1 = param_1 - param_3;
          param_2 = (param_2 - param_4) - (uint)bVar12;
          uVar3 = 1;
        }
        else {
          uVar3 = 0;
        }
        if (param_5 != (uint *)0x0) {
          *param_5 = param_1;
          param_5[1] = param_2;
        }
      }
      else {
        uVar9 = 0x20 - iVar4;
        uVar6 = param_3 >> (uVar9 & 0xff) | param_4 << iVar4;
        uVar2 = param_2 >> (uVar9 & 0xff);
        uVar3 = param_1 >> (uVar9 & 0xff) | param_2 << iVar4;
        uVar7 = uVar6 >> 0x10;
        param_1 = param_1 << iVar4;
        uVar10 = uVar2 / uVar7;
        uVar8 = uVar10 * (uVar6 & 0xffff);
        uVar5 = uVar3 >> 0x10 | (uVar2 - uVar7 * uVar10) * 0x10000;
        uVar2 = uVar10;
        if (uVar5 <= uVar8 && uVar8 - uVar5 != 0) {
          bVar12 = CARRY4(uVar6,uVar5);
          uVar5 = uVar6 + uVar5;
          uVar2 = uVar10 - 1;
          if ((!bVar12) && (uVar5 <= uVar8 && uVar8 - uVar5 != 0)) {
            uVar5 = uVar5 + uVar6;
            uVar2 = uVar10 - 2;
          }
        }
        uVar10 = (uVar5 - uVar8) / uVar7;
        uVar11 = uVar10 * (uVar6 & 0xffff);
        uVar5 = uVar3 & 0xffff | ((uVar5 - uVar8) - uVar7 * uVar10) * 0x10000;
        uVar3 = uVar10;
        if (uVar5 <= uVar11 && uVar11 - uVar5 != 0) {
          bVar12 = CARRY4(uVar6,uVar5);
          uVar5 = uVar6 + uVar5;
          uVar3 = uVar10 - 1;
          if ((!bVar12) && (uVar5 <= uVar11 && uVar11 - uVar5 != 0)) {
            uVar5 = uVar5 + uVar6;
            uVar3 = uVar10 - 2;
          }
        }
        uVar3 = uVar3 | uVar2 << 0x10;
        uVar1 = (ulonglong)uVar3 * (ulonglong)(param_3 << iVar4);
        if (CONCAT44(uVar5 - uVar11,param_1) < uVar1) {
          uVar1 = uVar1 - CONCAT44(uVar6,param_3 << iVar4);
          uVar3 = uVar3 - 1;
        }
        if (param_5 != (uint *)0x0) {
          uVar2 = ((uVar5 - uVar11) - (int)(uVar1 >> 0x20)) - (uint)(param_1 < (uint)uVar1);
          *param_5 = uVar2 << (uVar9 & 0xff) | param_1 - (uint)uVar1 >> iVar4;
          param_5[1] = uVar2 >> iVar4;
        }
      }
      uVar2 = 0;
    }
    goto LAB_0802b44a;
  }
  if (param_2 < param_3) {
    iVar4 = LZCOUNT(param_3);
    if (iVar4 != 0) {
      param_3 = param_3 << iVar4;
      param_2 = param_1 >> (0x20U - iVar4 & 0xff) | param_2 << iVar4;
      param_1 = param_1 << iVar4;
    }
    uVar10 = param_3 >> 0x10;
    uVar5 = param_2 / uVar10;
    uVar6 = uVar5 * (param_3 & 0xffff);
    uVar3 = param_1 >> 0x10 | (param_2 - uVar10 * uVar5) * 0x10000;
    uVar2 = uVar5;
    if (uVar3 <= uVar6 && uVar6 - uVar3 != 0) {
      bVar12 = CARRY4(param_3,uVar3);
      uVar3 = param_3 + uVar3;
      uVar2 = uVar5 - 1;
      if ((!bVar12) && (uVar3 <= uVar6 && uVar6 - uVar3 != 0)) {
        uVar3 = uVar3 + param_3;
        uVar2 = uVar5 - 2;
      }
    }
    uVar7 = (uVar3 - uVar6) / uVar10;
    uVar5 = uVar7 * (param_3 & 0xffff);
    uVar6 = param_1 & 0xffff | ((uVar3 - uVar6) - uVar10 * uVar7) * 0x10000;
    uVar3 = uVar7;
    if (uVar6 <= uVar5 && uVar5 - uVar6 != 0) {
      bVar12 = CARRY4(param_3,uVar6);
      uVar6 = param_3 + uVar6;
      uVar3 = uVar7 - 1;
      if ((!bVar12) && (uVar6 <= uVar5 && uVar5 - uVar6 != 0)) {
        uVar6 = uVar6 + param_3;
        uVar3 = uVar7 - 2;
      }
    }
    uVar6 = uVar6 - uVar5;
    uVar3 = uVar3 | uVar2 << 0x10;
    uVar2 = 0;
  }
  else {
    if (param_3 == 0) {
      iVar4 = 0x1f;
LAB_0802b464:
      param_3 = param_3 << iVar4;
      uVar2 = param_2 >> (0x20U - iVar4 & 0xff);
      uVar5 = param_1 >> (0x20U - iVar4 & 0xff) | param_2 << iVar4;
      uVar7 = param_3 >> 0x10;
      param_1 = param_1 << iVar4;
      uVar10 = uVar2 / uVar7;
      uVar6 = uVar10 * (param_3 & 0xffff);
      uVar2 = uVar5 >> 0x10 | (uVar2 - uVar7 * uVar10) * 0x10000;
      uVar3 = uVar10;
      if (uVar2 <= uVar6 && uVar6 - uVar2 != 0) {
        bVar12 = CARRY4(param_3,uVar2);
        uVar2 = param_3 + uVar2;
        uVar3 = uVar10 - 1;
        if ((!bVar12) && (uVar2 <= uVar6 && uVar6 - uVar2 != 0)) {
          uVar2 = uVar2 + param_3;
          uVar3 = uVar10 - 2;
        }
      }
      uVar8 = (uVar2 - uVar6) / uVar7;
      uVar10 = uVar8 * (param_3 & 0xffff);
      param_2 = uVar5 & 0xffff | ((uVar2 - uVar6) - uVar7 * uVar8) * 0x10000;
      uVar2 = uVar8;
      if (param_2 <= uVar10 && uVar10 - param_2 != 0) {
        bVar12 = CARRY4(param_3,param_2);
        param_2 = param_3 + param_2;
        uVar2 = uVar8 - 1;
        if ((!bVar12) && (param_2 <= uVar10 && uVar10 - param_2 != 0)) {
          param_2 = param_2 + param_3;
          uVar2 = uVar8 - 2;
        }
      }
      param_2 = param_2 - uVar10;
      uVar2 = uVar2 | uVar3 << 0x10;
    }
    else {
      iVar4 = LZCOUNT(param_3);
      if (iVar4 != 0) goto LAB_0802b464;
      param_2 = param_2 - param_3;
      uVar2 = 1;
      iVar4 = 0;
    }
    uVar7 = param_3 >> 0x10;
    uVar10 = param_2 / uVar7;
    uVar6 = uVar10 * (param_3 & 0xffff);
    uVar3 = param_1 >> 0x10 | (param_2 - uVar7 * uVar10) * 0x10000;
    uVar5 = uVar10;
    if (uVar3 <= uVar6 && uVar6 - uVar3 != 0) {
      bVar12 = CARRY4(param_3,uVar3);
      uVar3 = param_3 + uVar3;
      uVar5 = uVar10 - 1;
      if ((!bVar12) && (uVar3 <= uVar6 && uVar6 - uVar3 != 0)) {
        uVar3 = uVar3 + param_3;
        uVar5 = uVar10 - 2;
      }
    }
    uVar8 = (uVar3 - uVar6) / uVar7;
    uVar10 = uVar8 * (param_3 & 0xffff);
    uVar6 = param_1 & 0xffff | ((uVar3 - uVar6) - uVar7 * uVar8) * 0x10000;
    uVar3 = uVar8;
    if (uVar6 <= uVar10 && uVar10 - uVar6 != 0) {
      bVar12 = CARRY4(param_3,uVar6);
      uVar6 = param_3 + uVar6;
      uVar3 = uVar8 - 1;
      if ((!bVar12) && (uVar6 <= uVar10 && uVar10 - uVar6 != 0)) {
        uVar6 = uVar6 + param_3;
        uVar3 = uVar8 - 2;
      }
    }
    uVar6 = uVar6 - uVar10;
    uVar3 = uVar3 | uVar5 << 0x10;
  }
  if (param_5 != (uint *)0x0) {
    *param_5 = uVar6 >> iVar4;
    param_5[1] = 0;
  }
LAB_0802b44a:
  return CONCAT44(uVar2,uVar3);
}

