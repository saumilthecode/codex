
int FUN_08002bec(int *param_1,int param_2,int param_3,uint param_4)

{
  short sVar1;
  int iVar2;
  uint *puVar3;
  int iVar4;
  uint uVar5;
  undefined2 *puVar6;
  
  if (*(char *)((int)param_1 + 0x51) != '\x01') {
    return 2;
  }
  if (param_2 == 0) {
    return 1;
  }
  if (param_3 == 0) {
    return 1;
  }
  if ((param_1[1] == 0x104) && (param_1[2] == 0)) {
    *(undefined1 *)((int)param_1 + 0x51) = 4;
    iVar2 = FUN_08002800(param_1,param_2,param_2,param_3,param_4);
    return iVar2;
  }
  iVar2 = FUN_0800061c();
  if ((char)param_1[0x14] == '\x01') {
    return 2;
  }
  iVar4 = param_1[10];
  puVar3 = (uint *)*param_1;
  param_1[0xe] = param_2;
  *(undefined1 *)(param_1 + 0x14) = 1;
  *(undefined1 *)((int)param_1 + 0x51) = 4;
  param_1[0x10] = 0;
  param_1[0x11] = 0;
  param_1[0x15] = 0;
  param_1[0xc] = 0;
  *(undefined2 *)(param_1 + 0xd) = 0;
  *(short *)((int)param_1 + 0x3e) = (short)param_3;
  *(short *)(param_1 + 0xf) = (short)param_3;
  *(undefined2 *)((int)param_1 + 0x36) = 0;
  if (iVar4 == 0x2000) {
    *puVar3 = *puVar3 & 0xffffdfff;
    *puVar3 = *puVar3 | 0x2000;
    *(short *)((int)param_1 + 0x3e) = *(short *)((int)param_1 + 0x3e) + -1;
  }
  if (param_1[2] == 0x8000) {
    *puVar3 = *puVar3 & 0xffffffbf;
    *puVar3 = *puVar3 & 0xffffbfff;
  }
  if (-1 < (int)(*puVar3 << 0x19)) {
    *puVar3 = *puVar3 | 0x40;
  }
  if (param_1[3] == 0) {
    if (*(short *)((int)param_1 + 0x3e) != 0) {
      if (param_4 == 0xffffffff) {
        while( true ) {
          if ((int)(puVar3[2] << 0x1f) < 0) {
            *(char *)param_1[0xe] = (char)puVar3[3];
            *(short *)((int)param_1 + 0x3e) = *(short *)((int)param_1 + 0x3e) + -1;
            sVar1 = *(short *)((int)param_1 + 0x3e);
            param_1[0xe] = param_1[0xe] + 1;
          }
          else {
            FUN_0800061c();
            sVar1 = *(short *)((int)param_1 + 0x3e);
          }
          if (sVar1 == 0) break;
          puVar3 = (uint *)*param_1;
        }
      }
      else {
        while( true ) {
          if ((int)(puVar3[2] << 0x1f) < 0) {
            *(char *)param_1[0xe] = (char)puVar3[3];
            param_1[0xe] = param_1[0xe] + 1;
            *(short *)((int)param_1 + 0x3e) = *(short *)((int)param_1 + 0x3e) + -1;
          }
          else {
            iVar4 = FUN_0800061c();
            if (param_4 <= (uint)(iVar4 - iVar2)) goto LAB_08002dbe;
          }
          if (*(short *)((int)param_1 + 0x3e) == 0) break;
          puVar3 = (uint *)*param_1;
        }
      }
LAB_08002cbc:
      iVar4 = param_1[10];
    }
  }
  else if (*(short *)((int)param_1 + 0x3e) != 0) {
    if (param_4 == 0xffffffff) {
      while( true ) {
        uVar5 = puVar3[2];
        while ((int)(uVar5 << 0x1f) < 0) {
          puVar6 = (undefined2 *)param_1[0xe];
          *puVar6 = (short)puVar3[3];
          param_1[0xe] = (int)(puVar6 + 1);
          *(short *)((int)param_1 + 0x3e) = *(short *)((int)param_1 + 0x3e) + -1;
          if (*(short *)((int)param_1 + 0x3e) == 0) goto LAB_08002cbc;
          uVar5 = puVar3[2];
        }
        FUN_0800061c();
        if (*(short *)((int)param_1 + 0x3e) == 0) break;
        puVar3 = (uint *)*param_1;
      }
    }
    else {
      while( true ) {
        if ((int)(puVar3[2] << 0x1f) < 0) {
          puVar6 = (undefined2 *)param_1[0xe];
          *puVar6 = (short)puVar3[3];
          param_1[0xe] = (int)(puVar6 + 1);
          *(short *)((int)param_1 + 0x3e) = *(short *)((int)param_1 + 0x3e) + -1;
        }
        else {
          iVar4 = FUN_0800061c();
          if (param_4 <= (uint)(iVar4 - iVar2)) goto LAB_08002dbe;
        }
        if (*(short *)((int)param_1 + 0x3e) == 0) break;
        puVar3 = (uint *)*param_1;
      }
    }
    goto LAB_08002cbc;
  }
  if (iVar4 == 0x2000) {
    *(uint *)*param_1 = *(uint *)*param_1 | 0x1000;
    iVar4 = FUN_08002214(param_1,1,1,param_4,iVar2);
    if (iVar4 != 0) {
LAB_08002dc4:
      *(undefined1 *)(param_1 + 0x14) = 0;
      return 3;
    }
    if (param_1[3] == 0x800) {
      *(undefined2 *)param_1[0xe] = (short)*(undefined4 *)(*param_1 + 0xc);
    }
    else {
      *(undefined1 *)param_1[0xe] = *(undefined1 *)(*param_1 + 0xc);
    }
    iVar4 = FUN_08002214(param_1,1,1,param_4,iVar2);
    if (iVar4 != 0) {
      param_1[0x15] = param_1[0x15] | 2;
      *(undefined1 *)((int)param_1 + 0x51) = 1;
      goto LAB_08002dc4;
    }
  }
  if (param_1[1] == 0x104) {
    if (param_1[2] == 0x8000) {
      *(uint *)*param_1 = *(uint *)*param_1 & 0xffffffbf;
    }
    else if (param_1[2] == 0x400) {
      *(uint *)*param_1 = *(uint *)*param_1 & 0xffffffbf;
      iVar2 = FUN_08002214(param_1,1,0,param_4,iVar2);
      goto joined_r0x08002ebe;
    }
    iVar2 = FUN_08002214(param_1,0x80,0,param_4,iVar2);
  }
  else {
    iVar2 = FUN_08002214(param_1,1,0,param_4,iVar2);
  }
joined_r0x08002ebe:
  if (iVar2 != 0) {
    param_1[0x15] = param_1[0x15] | 0x20;
    param_1[0x15] = 0x20;
  }
  if (*(int *)(*param_1 + 8) << 0x1b < 0) {
    param_1[0x15] = param_1[0x15] | 2;
    *(undefined4 *)(*param_1 + 8) = 0xffef;
  }
  *(undefined1 *)((int)param_1 + 0x51) = 1;
  iVar2 = param_1[0x15];
  *(undefined1 *)(param_1 + 0x14) = 0;
  if (iVar2 != 0) {
    iVar2 = 1;
  }
  return iVar2;
LAB_08002dbe:
  *(undefined1 *)((int)param_1 + 0x51) = 1;
  goto LAB_08002dc4;
}

