
code * FUN_0802a304(undefined4 param_1,uint *param_2,undefined4 param_3,code *param_4,int *param_5)

{
  bool bVar1;
  int iVar2;
  code *pcVar3;
  int iVar4;
  undefined1 *puVar5;
  undefined4 uVar6;
  uint uVar7;
  uint uVar8;
  uint *puVar9;
  undefined4 *puVar10;
  uint uVar11;
  undefined1 *puVar12;
  byte bVar13;
  code *local_24;
  
  iVar2 = DAT_0802a53c;
  bVar13 = (byte)param_2[6];
  puVar5 = (undefined1 *)((int)param_2 + 0x43);
  local_24 = param_4;
  if (0x78 < bVar13) {
switchD_0802a340_caseD_65:
    *(byte *)((int)param_2 + 0x42) = bVar13;
LAB_0802a3ac:
    puVar5 = (undefined1 *)((int)param_2 + 0x42);
    uVar7 = 1;
LAB_0802a4ec:
    param_2[4] = uVar7;
    *(undefined1 *)((int)param_2 + 0x43) = 0;
    goto LAB_0802a448;
  }
  if (bVar13 < 99) {
    if (bVar13 == 0) goto LAB_0802a4ca;
    if (bVar13 == 0x58) goto LAB_0802a472;
    goto switchD_0802a340_caseD_65;
  }
  switch(bVar13) {
  case 99:
    uVar6 = *(undefined4 *)*param_5;
    *param_5 = (int)((undefined4 *)*param_5 + 1);
    *(char *)((int)param_2 + 0x42) = (char)uVar6;
    goto LAB_0802a3ac;
  case 100:
  case 0x69:
    puVar9 = (uint *)*param_5;
    uVar7 = *param_2;
    *param_5 = (int)(puVar9 + 1);
    if (((int)(uVar7 << 0x18) < 0) || (-1 < (int)(uVar7 << 0x19))) {
      uVar7 = *puVar9;
    }
    else {
      uVar7 = (uint)(short)*puVar9;
    }
    if ((int)uVar7 < 0) {
      uVar7 = -uVar7;
      *(undefined1 *)((int)param_2 + 0x43) = 0x2d;
    }
    uVar8 = 10;
    iVar2 = DAT_0802a53c;
    goto LAB_0802a3fc;
  default:
    goto switchD_0802a340_caseD_65;
  case 0x6e:
    puVar10 = (undefined4 *)*param_5;
    uVar8 = *param_2;
    uVar7 = param_2[5];
    *param_5 = (int)(puVar10 + 1);
    puVar9 = (uint *)*puVar10;
    if (((int)(uVar8 << 0x18) < 0) || (-1 < (int)(uVar8 << 0x19))) {
      *puVar9 = uVar7;
    }
    else {
      *(short *)puVar9 = (short)uVar7;
    }
LAB_0802a4ca:
    param_2[4] = 0;
    goto LAB_0802a448;
  case 0x6f:
  case 0x75:
    uVar7 = *(uint *)*param_5;
    if ((-1 < (int)(*param_2 << 0x18)) && ((int)(*param_2 << 0x19) < 0)) {
      uVar7 = uVar7 & 0xffff;
    }
    *param_5 = (int)((uint *)*param_5 + 1);
    if (bVar13 == 0x6f) {
      uVar8 = 8;
    }
    else {
      uVar8 = 10;
    }
    break;
  case 0x70:
    *param_2 = *param_2 | 0x20;
  case 0x78:
    bVar13 = 0x78;
    iVar2 = DAT_0802a540;
LAB_0802a472:
    *(byte *)((int)param_2 + 0x45) = bVar13;
    uVar8 = *param_2;
    uVar7 = *(uint *)*param_5;
    if ((-1 < (int)(uVar8 << 0x18)) && ((int)(uVar8 << 0x19) < 0)) {
      uVar7 = uVar7 & 0xffff;
    }
    *param_5 = (int)((uint *)*param_5 + 1);
    if ((int)(uVar8 << 0x1f) < 0) {
      *param_2 = uVar8 | 0x20;
    }
    if (uVar7 == 0) {
      *param_2 = *param_2 & 0xffffffdf;
    }
    uVar8 = 0x10;
    break;
  case 0x73:
    puVar10 = (undefined4 *)*param_5;
    *param_5 = (int)(puVar10 + 1);
    puVar5 = (undefined1 *)*puVar10;
    iVar2 = FUN_08005e00(puVar5,0,param_2[1],puVar10,param_1,param_2,param_3);
    if (iVar2 != 0) {
      param_2[1] = iVar2 - (int)puVar5;
    }
    uVar7 = param_2[1];
    goto LAB_0802a4ec;
  }
  *(undefined1 *)((int)param_2 + 0x43) = 0;
LAB_0802a3fc:
  uVar11 = param_2[1];
  param_2[2] = uVar11;
  puVar12 = puVar5;
  if (((int)uVar11 < 0) || (*param_2 = *param_2 & 0xfffffffb, uVar11 != 0 || uVar7 != 0)) {
    do {
      puVar12 = puVar12 + -1;
      *puVar12 = *(undefined1 *)(iVar2 + (uVar7 - uVar8 * (uVar7 / uVar8)));
      bVar1 = uVar8 <= uVar7;
      uVar7 = uVar7 / uVar8;
    } while (bVar1);
  }
  if (((uVar8 == 8) && ((int)(*param_2 << 0x1f) < 0)) && ((int)param_2[1] <= (int)param_2[4])) {
    puVar12[-1] = 0x30;
    puVar12 = puVar12 + -1;
  }
  param_2[4] = (int)puVar5 - (int)puVar12;
  puVar5 = puVar12;
LAB_0802a448:
  iVar2 = FUN_0802a228(param_1,param_2,&local_24,param_3,param_4);
  if ((iVar2 == -1) || (iVar2 = (*param_4)(param_1,param_3,puVar5,param_2[4]), iVar2 == -1)) {
LAB_0802a45c:
    pcVar3 = (code *)0xffffffff;
  }
  else {
    if ((int)(*param_2 << 0x1e) < 0) {
      for (iVar2 = 0; iVar2 < (int)(param_2[3] - (int)local_24); iVar2 = iVar2 + 1) {
        iVar4 = (*param_4)(param_1,param_3,(int)param_2 + 0x19,1);
        if (iVar4 == -1) goto LAB_0802a45c;
      }
    }
    pcVar3 = (code *)param_2[3];
    if ((int)param_2[3] < (int)local_24) {
      pcVar3 = local_24;
    }
  }
  return pcVar3;
}

