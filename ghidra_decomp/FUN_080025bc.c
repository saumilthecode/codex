
int FUN_080025bc(int *param_1,ushort *param_2,int param_3,uint param_4)

{
  int iVar1;
  uint *puVar2;
  int iVar3;
  ushort *puVar4;
  int iVar5;
  uint uVar6;
  
  iVar1 = FUN_0800061c();
  if (*(char *)((int)param_1 + 0x51) != '\x01') {
    return 2;
  }
  if (param_2 == (ushort *)0x0) {
    return 1;
  }
  if (param_3 == 0) {
    return 1;
  }
  if ((char)param_1[0x14] == '\x01') {
    return 2;
  }
  *(undefined1 *)(param_1 + 0x14) = 1;
  puVar2 = (uint *)*param_1;
  param_1[0xc] = (int)param_2;
  *(undefined1 *)((int)param_1 + 0x51) = 3;
  param_1[0x10] = 0;
  param_1[0x11] = 0;
  param_1[0x15] = 0;
  *(short *)(param_1 + 0xd) = (short)param_3;
  *(short *)((int)param_1 + 0x36) = (short)param_3;
  param_1[0xe] = 0;
  *(undefined2 *)(param_1 + 0xf) = 0;
  *(undefined2 *)((int)param_1 + 0x3e) = 0;
  if (param_1[2] == 0x8000) {
    *puVar2 = *puVar2 & 0xffffffbf;
    *puVar2 = *puVar2 | 0x4000;
  }
  iVar5 = param_1[10];
  if (iVar5 == 0x2000) {
    *puVar2 = *puVar2 & 0xffffdfff;
    *puVar2 = *puVar2 | 0x2000;
  }
  if ((int)(*puVar2 << 0x19) < 0) {
    iVar3 = param_1[1];
    if (param_1[3] != 0x800) goto LAB_0800265a;
LAB_08002712:
    if ((iVar3 == 0) || (param_3 == 1)) {
      puVar2[3] = (uint)*param_2;
      param_1[0xc] = (int)(param_2 + 1);
      *(short *)((int)param_1 + 0x36) = *(short *)((int)param_1 + 0x36) + -1;
    }
    if (*(short *)((int)param_1 + 0x36) == 0) goto LAB_080026ac;
    if (param_4 == 0xffffffff) {
      while( true ) {
        uVar6 = puVar2[2];
        while ((int)(uVar6 << 0x1e) < 0) {
          puVar4 = (ushort *)param_1[0xc];
          puVar2[3] = (uint)*puVar4;
          param_1[0xc] = (int)(puVar4 + 1);
          *(short *)((int)param_1 + 0x36) = *(short *)((int)param_1 + 0x36) + -1;
          if (*(short *)((int)param_1 + 0x36) == 0) goto LAB_080026aa;
          uVar6 = puVar2[2];
        }
        FUN_0800061c();
        if (*(short *)((int)param_1 + 0x36) == 0) break;
        puVar2 = (uint *)*param_1;
      }
    }
    else {
      while( true ) {
        if ((int)(puVar2[2] << 0x1e) < 0) {
          puVar4 = (ushort *)param_1[0xc];
          puVar2[3] = (uint)*puVar4;
          param_1[0xc] = (int)(puVar4 + 1);
          *(short *)((int)param_1 + 0x36) = *(short *)((int)param_1 + 0x36) + -1;
        }
        else {
          iVar5 = FUN_0800061c();
          if (param_4 <= (uint)(iVar5 - iVar1)) goto LAB_080027dc;
        }
        if (*(short *)((int)param_1 + 0x36) == 0) break;
        puVar2 = (uint *)*param_1;
      }
    }
  }
  else {
    iVar3 = param_1[1];
    *puVar2 = *puVar2 | 0x40;
    if (param_1[3] == 0x800) goto LAB_08002712;
LAB_0800265a:
    if ((iVar3 == 0) || (param_3 == 1)) {
      *(char *)(puVar2 + 3) = (char)*param_2;
      param_1[0xc] = param_1[0xc] + 1;
      *(short *)((int)param_1 + 0x36) = *(short *)((int)param_1 + 0x36) + -1;
    }
    if (*(short *)((int)param_1 + 0x36) != 0) {
      if (param_4 == 0xffffffff) {
        do {
          while (-1 < *(int *)(*param_1 + 8) << 0x1e) {
            FUN_0800061c();
            if (*(short *)((int)param_1 + 0x36) == 0) goto LAB_080026aa;
          }
          *(undefined1 *)(*param_1 + 0xc) = *(undefined1 *)param_1[0xc];
          *(short *)((int)param_1 + 0x36) = *(short *)((int)param_1 + 0x36) + -1;
          param_1[0xc] = param_1[0xc] + 1;
        } while (*(short *)((int)param_1 + 0x36) != 0);
      }
      else {
        do {
          if (*(int *)(*param_1 + 8) << 0x1e < 0) {
            *(undefined1 *)(*param_1 + 0xc) = *(undefined1 *)param_1[0xc];
            param_1[0xc] = param_1[0xc] + 1;
            *(short *)((int)param_1 + 0x36) = *(short *)((int)param_1 + 0x36) + -1;
          }
          else {
            iVar5 = FUN_0800061c();
            if (param_4 <= (uint)(iVar5 - iVar1)) {
LAB_080027dc:
              *(undefined1 *)((int)param_1 + 0x51) = 1;
              *(undefined1 *)(param_1 + 0x14) = 0;
              return 3;
            }
          }
        } while (*(short *)((int)param_1 + 0x36) != 0);
      }
    }
  }
LAB_080026aa:
  iVar5 = param_1[10];
LAB_080026ac:
  if (iVar5 == 0x2000) {
    *(uint *)*param_1 = *(uint *)*param_1 | 0x1000;
  }
  iVar1 = FUN_080022ec(param_1,param_4,iVar1);
  if (iVar1 != 0) {
    param_1[0x15] = 0x20;
  }
  *(undefined1 *)((int)param_1 + 0x51) = 1;
  iVar1 = param_1[0x15];
  *(undefined1 *)(param_1 + 0x14) = 0;
  if (iVar1 != 0) {
    iVar1 = 1;
  }
  return iVar1;
}

