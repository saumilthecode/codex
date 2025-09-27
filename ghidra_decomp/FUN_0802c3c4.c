
int * FUN_0802c3c4(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4,int param_5,
                  int param_6,undefined4 *param_7,int *param_8,uint param_9,int *param_10,
                  int *param_11,int param_12)

{
  byte *pbVar1;
  char *pcVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint *puVar6;
  undefined4 uVar7;
  byte *pbVar8;
  int *piVar9;
  undefined4 uVar10;
  int iVar11;
  int *piVar12;
  char *pcVar13;
  char *pcVar14;
  undefined8 uVar15;
  undefined8 uVar16;
  undefined1 auStack_30 [4];
  char *local_2c [2];
  
  if (param_4 < 0) {
    param_4 = param_4 + -0x80000000;
    uVar10 = 0x2d;
  }
  else {
    uVar10 = 0;
  }
  *param_7 = uVar10;
  switch(param_9) {
  case 0x41:
  case 0x61:
    uVar15 = FUN_0802e714(param_3,param_4,param_8);
    uVar15 = FUN_08006228((int)uVar15,(int)((ulonglong)uVar15 >> 0x20),0,0x3fc00000);
    iVar3 = FUN_080066f8((int)uVar15,(int)((ulonglong)uVar15 >> 0x20),0);
    if (iVar3 != 0) {
      *param_8 = 1;
    }
    iVar3 = DAT_0802c64c;
    if (param_9 != 0x61) {
      iVar3 = DAT_0802c650;
    }
    iVar11 = param_5 + -1;
    piVar9 = param_11;
    do {
      piVar12 = piVar9;
      iVar5 = iVar11;
      uVar15 = FUN_08006228((int)uVar15,(int)((ulonglong)uVar15 >> 0x20),0,DAT_0802c654);
      iVar4 = FUN_08006b60();
      uVar16 = FUN_08006154();
      uVar15 = FUN_08005eb8((int)uVar15,(int)((ulonglong)uVar15 >> 0x20),(int)uVar16,
                            (int)((ulonglong)uVar16 >> 0x20));
      uVar7 = (undefined4)((ulonglong)uVar15 >> 0x20);
      uVar10 = (undefined4)uVar15;
      iVar11 = *(int *)(iVar3 + iVar4 * 4);
      piVar9 = piVar12 + 1;
      *piVar12 = iVar11;
      if (iVar5 == -1) {
        iVar5 = FUN_08006748(uVar10,uVar7,0,DAT_0802c658);
        if ((iVar5 != 0) ||
           ((iVar5 = FUN_080066f8(uVar10,uVar7,0,DAT_0802c658), iVar5 != 0 && (iVar4 << 0x1f < 0))))
        {
          iVar4 = *(int *)(iVar3 + 0x3c);
          while (iVar11 == iVar4) {
            *piVar12 = 0x30;
            piVar12 = piVar12 + -1;
            iVar11 = *piVar12;
          }
          if (iVar11 == 0x39) {
            iVar11 = *(int *)(iVar3 + 0x28);
          }
          else {
            iVar11 = iVar11 + 1;
          }
          *piVar12 = iVar11;
        }
        goto LAB_0802c5bc;
      }
      iVar11 = iVar5 + -1;
      iVar4 = FUN_080066f8(uVar10,uVar7,0,0);
    } while (iVar4 == 0);
    if (-1 < iVar5) {
      do {
        iVar11 = iVar11 + -1;
        *piVar9 = 0x30;
        piVar9 = piVar9 + 1;
      } while (iVar11 != -2);
      piVar9 = piVar12 + iVar5 + 2;
    }
LAB_0802c5bc:
    *param_10 = (int)piVar9 - (int)param_11 >> 2;
    return param_11;
  default:
    pcVar2 = (char *)FUN_0802e8b0(param_1,param_2,param_3,param_4,2,param_5,param_8,auStack_30,
                                  local_2c);
    pcVar14 = local_2c[0];
    if (-1 < param_6 << 0x1f) goto LAB_0802c486;
    pcVar13 = pcVar2 + param_5;
    goto LAB_0802c460;
  case 0x45:
  case 0x65:
    param_5 = param_5 + 1;
    uVar10 = 2;
    break;
  case 0x46:
  case 0x66:
    uVar10 = 3;
  }
  pcVar2 = (char *)FUN_0802e8b0(param_1,param_2,param_3,param_4,uVar10,param_5,param_8,auStack_30,
                                local_2c);
  pcVar13 = pcVar2 + param_5;
  if ((param_9 & 0xffffffdf) == 0x46) {
    if (*pcVar2 == '0') {
      iVar3 = FUN_080066f8(param_3,param_4,0,0);
      if (iVar3 != 0) {
        pcVar14 = pcVar13 + *param_8;
        goto LAB_0802c486;
      }
      *param_8 = 1 - param_5;
      pcVar13 = pcVar13 + (1 - param_5);
    }
    else {
      pcVar13 = pcVar13 + *param_8;
    }
  }
LAB_0802c460:
  iVar3 = FUN_080066f8(param_3,param_4,0,0);
  pcVar14 = pcVar13;
  if (iVar3 == 0) {
    for (; pcVar14 = local_2c[0], local_2c[0] < pcVar13; local_2c[0] = local_2c[0] + 1) {
      *local_2c[0] = '0';
    }
  }
LAB_0802c486:
  *param_10 = (int)pcVar14 - (int)pcVar2;
  if (0 < (int)pcVar14 - (int)pcVar2) {
    puVar6 = (uint *)(param_11 + -1);
    pbVar8 = (byte *)(pcVar2 + -1);
    do {
      pbVar1 = pbVar8 + 1;
      puVar6 = puVar6 + 1;
      *puVar6 = (uint)*pbVar1;
      if (*param_10 <= (int)(pbVar8 + (2 - (int)pcVar2))) {
        return param_11;
      }
      pbVar8 = pbVar1;
    } while (pbVar1 != (byte *)(pcVar2 + param_12 + -1));
  }
  return param_11;
}

