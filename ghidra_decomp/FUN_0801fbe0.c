
void FUN_0801fbe0(ushort *param_1,int param_2)

{
  ushort uVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  ushort *puVar5;
  ushort *puVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  bool bVar10;
  
  uVar1 = *param_1;
  uVar7 = ~(uint)uVar1 & 0x101;
  bVar10 = uVar7 == 0;
  if (bVar10) {
    uVar7 = *(int *)(param_2 + 8) + 0xc;
  }
  if (bVar10) {
    *(uint *)(param_2 + 8) = uVar7;
  }
  uVar7 = (uint)(byte)*param_1;
  if ((char)(byte)*param_1 < '\0') {
    uVar8 = *(byte *)((int)param_1 + 1) & 2;
    if ((*(byte *)((int)param_1 + 1) & 2) != 0) {
      uVar8 = *(int *)(param_2 + 0x14) % 100;
    }
    *(uint *)(param_2 + 0x14) = (*(int *)(param_1 + 2) + -0x13) * 100 + uVar8;
  }
  iVar4 = DAT_0801fd98;
  if ((uVar1 & 0x402) == 0x400) {
    if (((uVar7 & 0x18) != 0x18) && ((int)(uVar7 << 0x1d) < 0)) {
      iVar2 = FUN_0801fa4e(*(int *)(param_2 + 0x14) + 0x76c);
      iVar9 = 0;
      puVar6 = (ushort *)((-iVar2 & 0x1aU) + iVar4);
      while (puVar5 = puVar6 + 1, (int)(uint)*puVar6 <= *(int *)(param_2 + 0x1c)) {
        iVar9 = iVar9 + 1;
        puVar6 = puVar5;
      }
      bVar10 = -1 < (int)(uVar7 << 0x1c);
      if (bVar10) {
        puVar5 = (ushort *)(iVar9 + -1);
      }
      if (bVar10) {
        *(ushort **)(param_2 + 0x10) = puVar5;
      }
      if (-1 < (int)(uVar7 << 0x1b)) {
        *(uint *)(param_2 + 0xc) =
             (*(int *)(param_2 + 0x1c) - (uint)*(ushort *)(iVar4 + (iVar2 * 0xd + iVar9 + -1) * 2))
             + 1;
      }
      *(byte *)param_1 = (byte)*param_1 & 0xe7 | 0x18;
    }
    uVar7 = (uint)(byte)*param_1;
    if (((int)(uVar7 << 0x1c) < 0) || (*(uint *)(param_2 + 0x10) < 0xc)) {
      uVar3 = FUN_0801fa78(*(undefined4 *)(param_2 + 0x14),*(uint *)(param_2 + 0x10),
                           *(undefined4 *)(param_2 + 0xc));
      *(undefined4 *)(param_2 + 0x18) = uVar3;
    }
  }
  if (((*param_1 & 0x404) == 0x400) &&
     ((uVar8 = *(uint *)(param_2 + 0x10), (int)(uVar7 << 0x1c) < 0 || (uVar8 < 0xc)))) {
    iVar4 = FUN_0801fa4e(*(int *)(param_2 + 0x14) + 0x76c);
    *(uint *)(param_2 + 0x1c) =
         *(int *)(param_2 + 0xc) + -1 + (uint)*(ushort *)(DAT_0801fd98 + (iVar4 * 0xd + uVar8) * 2);
  }
  if (((uVar7 & 0x60) != 0) && ((int)(uVar7 << 0x1e) < 0)) {
    iVar4 = *(int *)(param_2 + 0x14);
    if ((uVar7 & 4) == 0) {
      iVar2 = FUN_0801fa78(iVar4,0,1);
      uVar8 = (uVar7 << 0x1a) >> 0x1f ^ 1;
      *(uint *)(param_2 + 0x1c) =
           (7 - (iVar2 - uVar8)) % 7 + (((byte)param_1[1] & 0x3f) - 1) * 7 +
           (int)((*(int *)(param_2 + 0x18) - uVar8) + 7) % 7;
    }
    if ((uVar7 & 0x18) != 0x18) {
      iVar2 = FUN_0801fa4e(iVar4 + 0x76c);
      iVar4 = DAT_0801fd98;
      iVar9 = 0;
      puVar6 = (ushort *)((-iVar2 & 0x1aU) + DAT_0801fd98);
      while (puVar5 = puVar6 + 1, (int)(uint)*puVar6 <= *(int *)(param_2 + 0x1c)) {
        iVar9 = iVar9 + 1;
        puVar6 = puVar5;
      }
      bVar10 = -1 < (int)(uVar7 << 0x1c);
      if (bVar10) {
        puVar5 = (ushort *)(iVar9 + -1);
      }
      if (bVar10) {
        *(ushort **)(param_2 + 0x10) = puVar5;
      }
      if (-1 < (int)(uVar7 << 0x1b)) {
        *(uint *)(param_2 + 0xc) =
             (*(int *)(param_2 + 0x1c) - (uint)*(ushort *)(iVar4 + (iVar2 * 0xd + iVar9 + -1) * 2))
             + 1;
      }
    }
  }
  return;
}

