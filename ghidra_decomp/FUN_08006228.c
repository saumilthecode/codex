
ulonglong FUN_08006228(undefined4 param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint unaff_r5;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  bool bVar10;
  bool bVar11;
  bool bVar12;
  ulonglong uVar13;
  
  uVar13 = CONCAT44(param_2,param_1);
  uVar8 = 0x7ff;
  uVar4 = param_2 >> 0x14 & 0x7ff;
  bVar10 = uVar4 == 0;
  if (!bVar10) {
    unaff_r5 = param_4 >> 0x14 & 0x7ff;
    bVar10 = unaff_r5 == 0;
  }
  if (!bVar10) {
    bVar10 = uVar4 == 0x7ff;
  }
  if (!bVar10) {
    bVar10 = unaff_r5 == 0x7ff;
  }
  if (bVar10) {
    uVar13 = FUN_08006404();
  }
  uVar3 = (uint)(uVar13 >> 0x20);
  uVar7 = (uint)uVar13;
  iVar5 = uVar4 + unaff_r5;
  uVar4 = uVar3 ^ param_4;
  uVar3 = uVar3 & ~(uVar8 << 0x15);
  param_4 = param_4 & ~(uVar8 << 0x15);
  bVar10 = (uVar3 & 0xfffff) == 0;
  bVar11 = uVar7 == 0 && bVar10;
  if (uVar7 != 0 || !bVar10) {
    bVar11 = param_3 == 0 && (param_4 & 0xfffff) == 0;
  }
  uVar3 = uVar3 | 0x100000;
  param_4 = param_4 | 0x100000;
  if (bVar11) {
    uVar7 = uVar7 | param_3;
    param_4 = (uVar4 & 0x80000000 | uVar3) ^ param_4;
    uVar4 = uVar8 >> 1;
    bVar11 = SBORROW4(iVar5,uVar4);
    uVar6 = iVar5 - uVar4;
    bVar10 = uVar6 == 0;
    uVar3 = uVar6;
    if (!bVar10 && (int)uVar4 <= iVar5) {
      bVar11 = SBORROW4(uVar8,uVar6);
      uVar3 = uVar8 - uVar6;
      bVar10 = uVar8 == uVar6;
    }
    if (!bVar10 && (int)uVar3 < 0 == bVar11) {
      return CONCAT44(param_4 | uVar6 * 0x100000,uVar7);
    }
    param_4 = param_4 | 0x100000;
    uVar8 = 0;
    bVar11 = SBORROW4(uVar6,1);
    uVar6 = uVar6 - 1;
    bVar10 = uVar6 == 0;
    uVar4 = uVar6;
  }
  else {
    uVar1 = (uVar13 & 0xffffffff) * (ulonglong)param_3;
    uVar13 = (uVar13 & 0xffffffff) * (ulonglong)param_4 +
             (ulonglong)uVar3 * (ulonglong)param_3 + (uVar1 >> 0x20);
    uVar9 = (uint)uVar13;
    lVar2 = (ulonglong)uVar3 * (ulonglong)param_4 + (uVar13 >> 0x20);
    uVar8 = (uint)lVar2;
    uVar7 = (uint)((ulonglong)lVar2 >> 0x20);
    if ((int)uVar1 != 0) {
      uVar9 = uVar9 | 1;
    }
    uVar6 = (iVar5 + -0x3ff) - (uint)(uVar7 < 0x200);
    if (uVar7 < 0x200) {
      bVar10 = (uVar9 & 0x80000000) != 0;
      uVar9 = uVar9 << 1;
      lVar2 = CONCAT44(uVar7 * 2 + (uint)(CARRY4(uVar8,uVar8) || CARRY4(uVar8 * 2,(uint)bVar10)),
                       uVar8 * 2 + (uint)bVar10);
    }
    param_4 = uVar4 & 0x80000000 | (int)((ulonglong)lVar2 >> 0x20) << 0xb | (uint)lVar2 >> 0x15;
    uVar7 = (uint)lVar2 << 0xb | uVar9 >> 0x15;
    uVar8 = uVar9 * 0x800;
    bVar12 = 0xfc < uVar6;
    bVar11 = SBORROW4(uVar6,0xfd);
    uVar3 = uVar6 - 0xfd;
    bVar10 = uVar3 == 0;
    uVar4 = uVar3;
    if (bVar12 && !bVar10) {
      bVar12 = 0x6ff < uVar3;
      bVar11 = SBORROW4(uVar3,0x700);
      uVar4 = uVar6 - 0x7fd;
      bVar10 = uVar3 == 0x700;
    }
    if (!bVar12 || bVar10) {
      bVar10 = 0x7fffffff < uVar8;
      if (uVar8 == 0x80000000) {
        bVar10 = (uVar9 >> 0x15 & 1) != 0;
      }
      return CONCAT44(param_4 + uVar6 * 0x100000 + (uint)CARRY4(uVar7,(uint)bVar10),uVar7 + bVar10);
    }
  }
  if (!bVar10 && (int)uVar4 < 0 == bVar11) {
    return (ulonglong)(param_4 & 0x80000000 | 0x7ff00000) << 0x20;
  }
  if (uVar6 != 0xffffffca && (int)(uVar6 + 0x36) < 0 == SCARRY4(uVar6,0x36)) {
    uVar4 = -uVar6;
    uVar3 = uVar4 - 0x20;
    if (0x1f < (int)uVar4) {
      uVar6 = uVar7 >> (uVar3 & 0xff) | param_4 << (0x20 - uVar3 & 0xff);
      uVar4 = (param_4 >> (uVar3 & 0xff) & ~((param_4 & 0x80000000) >> (uVar3 & 0xff))) -
              ((int)uVar6 >> 0x1f);
      if ((uVar8 == 0 && uVar7 << (0x20 - uVar3 & 0xff) == 0) && (uVar6 & 0x7fffffff) == 0) {
        uVar4 = uVar4 & ~(uVar6 >> 0x1f);
      }
      return CONCAT44(param_4,uVar4) & 0x80000000ffffffff;
    }
    iVar5 = uVar4 - 0x14;
    if (iVar5 != 0 && iVar5 < 0 == SCARRY4(uVar3,0xc)) {
      uVar4 = 0xc - iVar5;
      uVar3 = uVar7 << (uVar4 & 0xff);
      uVar4 = uVar7 >> (0x20 - uVar4 & 0xff) | param_4 << (uVar4 & 0xff);
      uVar7 = uVar4 + -((int)uVar3 >> 0x1f);
      if (uVar8 == 0 && (uVar3 & 0x7fffffff) == 0) {
        uVar7 = uVar7 & ~(uVar3 >> 0x1f);
      }
      return CONCAT44((param_4 & 0x80000000) + (uint)CARRY4(uVar4,-((int)uVar3 >> 0x1f)),uVar7);
    }
    uVar9 = uVar7 << (uVar6 + 0x20 & 0xff);
    uVar7 = uVar7 >> (uVar4 & 0xff) | param_4 << (uVar6 + 0x20 & 0xff);
    uVar3 = uVar7 + -((int)uVar9 >> 0x1f);
    if (uVar8 == 0 && (uVar9 & 0x7fffffff) == 0) {
      uVar3 = uVar3 & ~(uVar9 >> 0x1f);
    }
    return CONCAT44((param_4 & 0x80000000) +
                    ((param_4 & 0x7fffffff) >> (uVar4 & 0xff)) +
                    (uint)CARRY4(uVar7,-((int)uVar9 >> 0x1f)),uVar3);
  }
  return (ulonglong)(param_4 & 0x80000000) << 0x20;
}

