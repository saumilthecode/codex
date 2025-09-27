
undefined4 FUN_08004974(undefined4 *param_1,ushort *param_2,int param_3,uint param_4)

{
  short sVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  byte bVar5;
  uint *puVar6;
  ushort *puVar7;
  ushort *puVar8;
  ushort *puVar9;
  
  if (*(char *)((int)param_1 + 0x42) != ' ') {
    return 2;
  }
  if ((param_2 == (ushort *)0x0) || (param_3 == 0)) {
    return 1;
  }
  param_1[0x11] = 0;
  *(undefined1 *)((int)param_1 + 0x42) = 0x22;
  param_1[0xc] = 0;
  iVar3 = FUN_0800061c();
  *(short *)(param_1 + 0xb) = (short)param_3;
  *(short *)((int)param_1 + 0x2e) = (short)param_3;
  if ((param_1[2] == 0x1000) && (param_1[4] == 0)) {
    puVar8 = (ushort *)0x0;
    puVar7 = param_2;
  }
  else {
    puVar7 = (ushort *)0x0;
    puVar8 = param_2;
  }
  sVar1 = *(short *)((int)param_1 + 0x2e);
  do {
    if (sVar1 == 0) {
      *(undefined1 *)((int)param_1 + 0x42) = 0x20;
      return 0;
    }
    puVar6 = (uint *)*param_1;
    if (param_4 == 0xffffffff) {
      do {
      } while (-1 < (int)(*puVar6 << 0x1a));
    }
    else if (param_4 == 0) {
      if (-1 < (int)(*puVar6 << 0x1a)) {
        FUN_0800061c();
        goto LAB_08004a4c;
      }
    }
    else {
      while ((*puVar6 & 0x20) == 0) {
        iVar4 = FUN_0800061c();
        if (param_4 < (uint)(iVar4 - iVar3)) goto LAB_08004a4c;
        puVar6 = (uint *)*param_1;
        if (((int)(puVar6[3] << 0x1d) < 0) && ((int)(*puVar6 << 0x1c) < 0)) goto LAB_08004a04;
      }
    }
    if (puVar8 == (ushort *)0x0) {
      puVar8 = puVar7 + 1;
      *puVar7 = (ushort)((puVar6[1] << 0x17) >> 0x17);
      puVar9 = (ushort *)0x0;
    }
    else {
      if ((param_1[2] == 0x1000) || ((param_1[2] == 0 && (param_1[4] == 0)))) {
        bVar5 = (byte)puVar6[1];
      }
      else {
        bVar5 = (byte)puVar6[1] & 0x7f;
      }
      puVar9 = (ushort *)((int)puVar8 + 1);
      *(byte *)puVar8 = bVar5;
      puVar8 = puVar7;
    }
    *(short *)((int)param_1 + 0x2e) = *(short *)((int)param_1 + 0x2e) + -1;
    sVar1 = *(short *)((int)param_1 + 0x2e);
    puVar7 = puVar8;
    puVar8 = puVar9;
  } while( true );
LAB_08004a04:
  do {
    ExclusiveAccess(puVar6 + 3);
    bVar2 = (bool)hasExclusiveAccess(puVar6 + 3);
  } while (!bVar2);
  puVar6[3] = puVar6[3] & 0xfffffedf;
  do {
    ExclusiveAccess(puVar6 + 5);
    bVar2 = (bool)hasExclusiveAccess(puVar6 + 5);
  } while (!bVar2);
  puVar6[5] = puVar6[5] & 0xfffffffe;
  if (param_1[0xc] == 1) {
    do {
      ExclusiveAccess(puVar6 + 3);
      bVar2 = (bool)hasExclusiveAccess(puVar6 + 3);
    } while (!bVar2);
    puVar6[3] = puVar6[3] & 0xffffffef;
  }
  *(undefined1 *)((int)param_1 + 0x42) = 0x20;
  *(undefined1 *)(param_1 + 0x10) = 0;
  param_1[0xc] = 0;
  param_1[0x11] = 8;
LAB_08004a4c:
  *(undefined1 *)((int)param_1 + 0x42) = 0x20;
  return 3;
}

