
undefined4 FUN_080024b0(undefined4 *param_1)

{
  char cVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  
  if (param_1 == (undefined4 *)0x0) {
    return 1;
  }
  uVar2 = param_1[9];
  if (uVar2 == 0) {
    if (param_1[1] != 0x104) {
      cVar1 = *(char *)((int)param_1 + 0x51);
      param_1[7] = 0;
      goto joined_r0x08002574;
    }
  }
  else {
    param_1[4] = 0;
    param_1[5] = 0;
  }
  cVar1 = *(char *)((int)param_1 + 0x51);
joined_r0x08002574:
  if (cVar1 == '\0') {
    *(undefined1 *)(param_1 + 0x14) = 0;
    FUN_080024ac(param_1);
    uVar2 = param_1[9];
  }
  uVar6 = param_1[1];
  uVar3 = param_1[2];
  uVar7 = param_1[3];
  uVar5 = param_1[6];
  *(undefined1 *)((int)param_1 + 0x51) = 2;
  uVar8 = param_1[4];
  uVar9 = param_1[5];
  puVar4 = (uint *)*param_1;
  uVar10 = param_1[7];
  uVar11 = param_1[8];
  uVar12 = param_1[10];
  *puVar4 = *puVar4 & 0xffffffbf;
  uVar3 = uVar6 & 0x104 | uVar3 & 0x8400 | uVar7 & 0x800 | uVar8 & 2 | uVar9 & 1 | uVar5 & 0x200 |
          uVar10 & 0x38 | uVar11 & 0x80 | uVar12 & 0x2000;
  *puVar4 = uVar3;
  if (uVar12 == 0x2000) {
    uVar3 = (uint)*(ushort *)(param_1 + 0xb);
  }
  puVar4[1] = uVar5 >> 0x10 & 4 | uVar2 & 0x10;
  if (uVar12 == 0x2000) {
    puVar4[4] = uVar3;
  }
  puVar4[7] = puVar4[7] & 0xfffff7ff;
  param_1[0x15] = 0;
  *(undefined1 *)((int)param_1 + 0x51) = 1;
  return 0;
}

