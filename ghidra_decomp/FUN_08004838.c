
undefined4 FUN_08004838(undefined4 *param_1,ushort *param_2,int param_3,uint param_4)

{
  undefined4 uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  ushort *puVar7;
  ushort *puVar9;
  ushort *puVar10;
  uint uVar11;
  ushort *puVar8;
  
  if (*(char *)((int)param_1 + 0x41) != ' ') {
    return 2;
  }
  if ((param_2 == (ushort *)0x0) || (param_3 == 0)) {
    uVar1 = 1;
  }
  else {
    param_1[0x11] = 0;
    *(undefined1 *)((int)param_1 + 0x41) = 0x21;
    uVar11 = param_4;
    uVar2 = FUN_0800061c();
    *(short *)(param_1 + 9) = (short)param_3;
    *(short *)((int)param_1 + 0x26) = (short)param_3;
    puVar7 = param_2;
    puVar9 = (ushort *)0x0;
    if ((param_1[2] == 0x1000) && (param_1[4] == 0)) {
      puVar7 = (ushort *)0x0;
      puVar9 = param_2;
    }
    piVar6 = (int *)*param_1;
    uVar4 = (uint)*(ushort *)((int)param_1 + 0x26);
    uVar3 = uVar2;
    if (uVar4 != 0) {
      if (param_4 == 0xffffffff) goto LAB_080048ca;
LAB_08004886:
      if (param_4 == 0) {
        uVar3 = *piVar6 << 0x18;
        if (-1 < (int)uVar3) goto LAB_0800491c;
      }
      else {
        iVar5 = *piVar6;
        while (-1 < iVar5 << 0x18) {
          iVar5 = FUN_0800061c();
          uVar3 = iVar5 - uVar2;
          if (param_4 < uVar3) goto LAB_08004920;
          piVar6 = (int *)*param_1;
          iVar5 = *piVar6;
        }
      }
      do {
        while (puVar8 = puVar7, puVar10 = puVar9, puVar7 == (ushort *)0x0) {
          do {
            puVar9 = puVar10 + 1;
            piVar6[1] = *puVar10 & 0x1ff;
            *(short *)((int)param_1 + 0x26) = *(short *)((int)param_1 + 0x26) + -1;
            uVar4 = (uint)*(ushort *)((int)param_1 + 0x26);
            if (uVar4 == 0) goto LAB_0800492c;
            if (param_4 != 0xffffffff) goto LAB_08004886;
            puVar10 = puVar9;
          } while (*piVar6 << 0x18 < 0);
          uVar3 = *piVar6 << 0x18;
          if (-1 < (int)uVar3) goto LAB_080048d0;
        }
        do {
          puVar7 = (ushort *)((int)puVar8 + 1);
          piVar6[1] = (uint)(byte)*puVar8;
          *(short *)((int)param_1 + 0x26) = *(short *)((int)param_1 + 0x26) + -1;
          uVar4 = (uint)*(ushort *)((int)param_1 + 0x26);
          if (uVar4 == 0) goto LAB_0800492c;
          if (param_4 != 0xffffffff) goto LAB_08004886;
          puVar8 = puVar7;
        } while (*piVar6 << 0x18 < 0);
LAB_080048ca:
        do {
          uVar3 = *piVar6 << 0x18;
          if ((int)uVar3 < 0) break;
LAB_080048d0:
          uVar3 = *piVar6 << 0x18;
        } while (-1 < (int)uVar3);
      } while( true );
    }
LAB_0800492c:
    if (param_4 == 0xffffffff) {
      do {
        if (*piVar6 << 0x19 < 0) break;
      } while (-1 < *piVar6 << 0x19);
    }
    else if (param_4 == 0) {
      if (-1 < *piVar6 << 0x19) {
LAB_0800491c:
        FUN_0800061c();
LAB_08004920:
        *(undefined1 *)((int)param_1 + 0x41) = 0x20;
        return 3;
      }
    }
    else {
      iVar5 = *piVar6;
      while (-1 < iVar5 << 0x19) {
        uVar3 = FUN_0800061c(uVar3,iVar5 << 0x19,uVar4,iVar5,uVar11);
        if (param_4 < uVar3 - uVar2) goto LAB_08004920;
        uVar4 = ((int *)*param_1)[3];
        iVar5 = *(int *)*param_1;
      }
    }
    *(undefined1 *)((int)param_1 + 0x41) = 0x20;
    uVar1 = 0;
  }
  return uVar1;
}

