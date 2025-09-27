
undefined4 FUN_08004e0c(undefined4 *param_1,ushort *param_2,int param_3,short *param_4,uint param_5)

{
  int iVar1;
  int iVar2;
  byte bVar3;
  int *piVar4;
  ushort *puVar5;
  ushort *puVar6;
  ushort *puVar7;
  
  if (*(char *)((int)param_1 + 0x42) != ' ') {
    return 2;
  }
  if ((param_2 == (ushort *)0x0) || (param_3 == 0)) {
    return 1;
  }
  param_1[0x11] = 0;
  *(undefined1 *)((int)param_1 + 0x42) = 0x22;
  param_1[0xc] = 1;
  param_1[0xd] = 0;
  iVar1 = FUN_0800061c();
  *(short *)(param_1 + 0xb) = (short)param_3;
  *(short *)((int)param_1 + 0x2e) = (short)param_3;
  puVar5 = param_2;
  puVar6 = (ushort *)0x0;
  if ((param_1[2] == 0x1000) && (param_1[4] == 0)) {
    puVar5 = (ushort *)0x0;
    puVar6 = param_2;
  }
  *param_4 = 0;
  if (*(short *)((int)param_1 + 0x2e) != 0) {
    if (param_5 == 0xffffffff) {
      do {
        piVar4 = (int *)*param_1;
        if ((*piVar4 << 0x1b < 0) && (*param_4 != 0)) {
LAB_08004f82:
          param_1[0xd] = 2;
          *(undefined1 *)((int)param_1 + 0x42) = 0x20;
          return 0;
        }
        puVar7 = puVar6;
        if (*piVar4 << 0x1a < 0) {
          if (puVar5 == (ushort *)0x0) {
            puVar7 = puVar6 + 1;
            *puVar6 = (ushort)((uint)(piVar4[1] << 0x17) >> 0x17);
          }
          else {
            if ((param_1[2] == 0x1000) || ((param_1[2] == 0 && (param_1[4] == 0)))) {
              bVar3 = (byte)piVar4[1];
            }
            else {
              bVar3 = (byte)piVar4[1] & 0x7f;
            }
            *(byte *)puVar5 = bVar3;
            puVar5 = (ushort *)((int)puVar5 + 1);
          }
          *param_4 = *param_4 + 1;
          *(short *)((int)param_1 + 0x2e) = *(short *)((int)param_1 + 0x2e) + -1;
        }
        puVar6 = puVar7;
      } while (*(short *)((int)param_1 + 0x2e) != 0);
    }
    else {
      do {
        piVar4 = (int *)*param_1;
        if ((*piVar4 << 0x1b < 0) && (*param_4 != 0)) goto LAB_08004f82;
        puVar7 = puVar6;
        if (*piVar4 << 0x1a < 0) {
          if (puVar5 == (ushort *)0x0) {
            puVar7 = puVar6 + 1;
            *puVar6 = (ushort)((uint)(piVar4[1] << 0x17) >> 0x17);
          }
          else {
            if ((param_1[2] == 0x1000) || ((param_1[2] == 0 && (param_1[4] == 0)))) {
              bVar3 = (byte)piVar4[1];
            }
            else {
              bVar3 = (byte)piVar4[1] & 0x7f;
            }
            *(byte *)puVar5 = bVar3;
            puVar5 = (ushort *)((int)puVar5 + 1);
          }
          *param_4 = *param_4 + 1;
          *(short *)((int)param_1 + 0x2e) = *(short *)((int)param_1 + 0x2e) + -1;
        }
        iVar2 = FUN_0800061c();
        if ((param_5 < (uint)(iVar2 - iVar1)) || (param_5 == 0)) {
          *(undefined1 *)((int)param_1 + 0x42) = 0x20;
          return 3;
        }
        puVar6 = puVar7;
      } while (*(short *)((int)param_1 + 0x2e) != 0);
    }
  }
  *param_4 = *(short *)(param_1 + 0xb) - *(short *)((int)param_1 + 0x2e);
  *(undefined1 *)((int)param_1 + 0x42) = 0x20;
  return 0;
}

