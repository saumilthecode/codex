
undefined4 FUN_08002800(int *param_1,ushort *param_2,int param_3,int param_4,uint param_5)

{
  undefined2 uVar1;
  int iVar2;
  int iVar3;
  undefined2 *puVar4;
  ushort *puVar5;
  int iVar6;
  uint *puVar7;
  uint uVar8;
  uint uVar9;
  
  iVar2 = FUN_0800061c();
  iVar6 = param_1[1];
  if ((*(char *)((int)param_1 + 0x51) != '\x01') &&
     (((iVar6 != 0x104 || (param_1[2] != 0)) || (*(char *)((int)param_1 + 0x51) != '\x04')))) {
    return 2;
  }
  if (param_2 == (ushort *)0x0) {
    return 1;
  }
  if (param_3 == 0) {
    return 1;
  }
  if (param_4 == 0) {
    return 1;
  }
  if ((char)param_1[0x14] == '\x01') {
    return 2;
  }
  param_1[0xe] = param_3;
  *(undefined1 *)(param_1 + 0x14) = 1;
  iVar3 = param_1[10];
  uVar1 = (undefined2)param_4;
  *(undefined2 *)(param_1 + 0xf) = uVar1;
  if (*(char *)((int)param_1 + 0x51) != '\x04') {
    *(undefined1 *)((int)param_1 + 0x51) = 5;
  }
  param_1[0x15] = 0;
  param_1[0x10] = 0;
  *(undefined2 *)((int)param_1 + 0x3e) = uVar1;
  param_1[0x11] = 0;
  param_1[0xc] = (int)param_2;
  puVar7 = (uint *)*param_1;
  *(undefined2 *)(param_1 + 0xd) = uVar1;
  *(undefined2 *)((int)param_1 + 0x36) = uVar1;
  if (iVar3 == 0x2000) {
    *puVar7 = *puVar7 & 0xffffdfff;
    *puVar7 = *puVar7 | 0x2000;
  }
  if (-1 < (int)(*puVar7 << 0x19)) {
    *puVar7 = *puVar7 | 0x40;
  }
  if (param_1[3] == 0x800) {
    if ((iVar6 == 0) || (param_4 == 1)) {
      puVar7[3] = (uint)*param_2;
      param_1[0xc] = (int)(param_2 + 1);
      *(short *)((int)param_1 + 0x36) = *(short *)((int)param_1 + 0x36) + -1;
      if ((*(short *)((int)param_1 + 0x36) == 0) && (iVar3 == 0x2000)) {
        *puVar7 = *puVar7 | 0x1000;
      }
    }
    uVar9 = 1;
    if (param_5 == 0xffffffff) {
      while ((*(short *)((int)param_1 + 0x36) != 0 || (*(short *)((int)param_1 + 0x3e) != 0))) {
        puVar7 = (uint *)*param_1;
        if (((int)(puVar7[2] << 0x1e) < 0) && (*(short *)((int)param_1 + 0x36) != 0)) {
          if (uVar9 != 0) {
            puVar5 = (ushort *)param_1[0xc];
            puVar7[3] = (uint)*puVar5;
            param_1[0xc] = (int)(puVar5 + 1);
            *(short *)((int)param_1 + 0x36) = *(short *)((int)param_1 + 0x36) + -1;
            if ((*(short *)((int)param_1 + 0x36) == 0) && (param_1[10] == 0x2000)) {
              *puVar7 = *puVar7 | 0x1000;
            }
          }
          uVar9 = 0;
        }
        uVar8 = puVar7[2];
        if (((uVar8 & 1) != 0) && (*(short *)((int)param_1 + 0x3e) != 0)) {
          puVar4 = (undefined2 *)param_1[0xe];
          *puVar4 = (short)puVar7[3];
          param_1[0xe] = (int)(puVar4 + 1);
          *(short *)((int)param_1 + 0x3e) = *(short *)((int)param_1 + 0x3e) + -1;
          uVar9 = uVar8 & 1;
        }
        FUN_0800061c();
      }
      goto LAB_08002928;
    }
    do {
      if ((*(short *)((int)param_1 + 0x36) == 0) && (*(short *)((int)param_1 + 0x3e) == 0))
      goto LAB_08002928;
      puVar7 = (uint *)*param_1;
      if (((int)(puVar7[2] << 0x1e) < 0) && (*(short *)((int)param_1 + 0x36) != 0)) {
        if (uVar9 != 0) {
          puVar5 = (ushort *)param_1[0xc];
          puVar7[3] = (uint)*puVar5;
          param_1[0xc] = (int)(puVar5 + 1);
          *(short *)((int)param_1 + 0x36) = *(short *)((int)param_1 + 0x36) + -1;
          if ((*(short *)((int)param_1 + 0x36) == 0) && (param_1[10] == 0x2000)) {
            *puVar7 = *puVar7 | 0x1000;
          }
        }
        uVar9 = 0;
      }
      uVar8 = puVar7[2];
      if (((uVar8 & 1) != 0) && (*(short *)((int)param_1 + 0x3e) != 0)) {
        puVar4 = (undefined2 *)param_1[0xe];
        *puVar4 = (short)puVar7[3];
        param_1[0xe] = (int)(puVar4 + 1);
        *(short *)((int)param_1 + 0x3e) = *(short *)((int)param_1 + 0x3e) + -1;
        uVar9 = uVar8 & 1;
      }
      iVar6 = FUN_0800061c();
    } while ((uint)(iVar6 - iVar2) < param_5);
  }
  else {
    if ((iVar6 == 0) || (param_4 == 1)) {
      *(char *)(puVar7 + 3) = (char)*param_2;
      *(short *)((int)param_1 + 0x36) = *(short *)((int)param_1 + 0x36) + -1;
      param_1[0xc] = param_1[0xc] + 1;
      if ((*(short *)((int)param_1 + 0x36) == 0) && (param_1[10] == 0x2000)) {
        *(uint *)*param_1 = *(uint *)*param_1 | 0x1000;
      }
    }
    uVar9 = 1;
    if (param_5 == 0xffffffff) {
      while ((*(short *)((int)param_1 + 0x36) != 0 || (*(short *)((int)param_1 + 0x3e) != 0))) {
        puVar7 = (uint *)*param_1;
        if (((int)(puVar7[2] << 0x1e) < 0) &&
           ((*(short *)((int)param_1 + 0x36) != 0 && (uVar9 != 0)))) {
          *(undefined1 *)(puVar7 + 3) = *(undefined1 *)param_1[0xc];
          puVar7 = (uint *)*param_1;
          *(short *)((int)param_1 + 0x36) = *(short *)((int)param_1 + 0x36) + -1;
          param_1[0xc] = param_1[0xc] + 1;
          if ((*(short *)((int)param_1 + 0x36) == 0) && (param_1[10] == 0x2000)) {
            *puVar7 = *puVar7 | 0x1000;
          }
          uVar9 = 0;
        }
        uVar8 = puVar7[2];
        if (((uVar8 & 1) != 0) && (*(short *)((int)param_1 + 0x3e) != 0)) {
          *(char *)param_1[0xe] = (char)puVar7[3];
          param_1[0xe] = param_1[0xe] + 1;
          *(short *)((int)param_1 + 0x3e) = *(short *)((int)param_1 + 0x3e) + -1;
          uVar9 = uVar8 & 1;
        }
        FUN_0800061c();
      }
LAB_08002928:
      iVar6 = param_1[10];
      if (iVar6 != 0x2000) {
        iVar3 = *param_1;
LAB_08002934:
        if ((*(uint *)(iVar3 + 8) & 0x10) != 0) {
          param_1[0x15] = param_1[0x15] | 2;
          *(undefined4 *)(iVar3 + 8) = 0xffef;
          *(undefined1 *)(param_1 + 0x14) = 0;
          return 1;
        }
        iVar2 = FUN_080022ec(param_1,param_5,iVar2,iVar6);
        if (iVar2 != 0) {
          param_1[0x15] = 0x20;
          *(undefined1 *)(param_1 + 0x14) = 0;
          return 1;
        }
        *(undefined1 *)((int)param_1 + 0x51) = 1;
        *(undefined1 *)(param_1 + 0x14) = 0;
        if (param_1[0x15] != 0) {
          return 1;
        }
        return 0;
      }
      iVar6 = FUN_08002214(param_1,1,1,param_5,iVar2);
      if (iVar6 == 0) {
        iVar3 = *param_1;
        iVar6 = *(int *)(iVar3 + 0xc);
        goto LAB_08002934;
      }
      param_1[0x15] = param_1[0x15] | 2;
      *(undefined1 *)((int)param_1 + 0x51) = 1;
      goto LAB_08002a7a;
    }
    do {
      if ((*(short *)((int)param_1 + 0x36) == 0) && (*(short *)((int)param_1 + 0x3e) == 0))
      goto LAB_08002928;
      puVar7 = (uint *)*param_1;
      if ((((int)(puVar7[2] << 0x1e) < 0) && (*(short *)((int)param_1 + 0x36) != 0)) && (uVar9 != 0)
         ) {
        *(undefined1 *)(puVar7 + 3) = *(undefined1 *)param_1[0xc];
        *(short *)((int)param_1 + 0x36) = *(short *)((int)param_1 + 0x36) + -1;
        puVar7 = (uint *)*param_1;
        param_1[0xc] = param_1[0xc] + 1;
        if ((*(short *)((int)param_1 + 0x36) == 0) && (param_1[10] == 0x2000)) {
          *puVar7 = *puVar7 | 0x1000;
        }
        uVar9 = 0;
      }
      uVar8 = puVar7[2];
      if (((uVar8 & 1) != 0) && (*(short *)((int)param_1 + 0x3e) != 0)) {
        *(char *)param_1[0xe] = (char)puVar7[3];
        param_1[0xe] = param_1[0xe] + 1;
        *(short *)((int)param_1 + 0x3e) = *(short *)((int)param_1 + 0x3e) + -1;
        uVar9 = uVar8 & 1;
      }
      iVar6 = FUN_0800061c();
    } while ((uint)(iVar6 - iVar2) < param_5);
  }
  *(undefined1 *)((int)param_1 + 0x51) = 1;
LAB_08002a7a:
  *(undefined1 *)(param_1 + 0x14) = 0;
  return 3;
}

