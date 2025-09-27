
uint FUN_0802643c(int param_1,uint param_2,uint *param_3)

{
  int iVar1;
  uint uVar2;
  ushort uVar3;
  uint uVar4;
  uint uVar5;
  
  if (param_2 == 0xffffffff) {
    return 0xffffffff;
  }
  if ((param_1 != 0) && (*(int *)(param_1 + 0x20) == 0)) {
    FUN_08025ec4();
  }
  if ((-1 < (int)(param_3[0x19] << 0x1f)) && (-1 < (int)((uint)(ushort)param_3[3] << 0x16))) {
    FUN_08028650(param_3[0x16]);
  }
  uVar2 = (uint)(short)(ushort)param_3[3];
  uVar3 = (ushort)param_3[3] & 0xffdf;
  *(ushort *)(param_3 + 3) = uVar3;
  if ((int)(uVar2 << 0x1d) < 0) {
LAB_080264bc:
    uVar2 = param_3[1];
    uVar5 = param_2 & 0xff;
    if (param_3[0xd] == 0) {
      uVar4 = *param_3;
      if (((param_3[4] == 0) || (uVar4 <= param_3[4])) || (*(byte *)(uVar4 - 1) != uVar5)) {
        param_3[0xf] = uVar4;
        param_3[0x10] = uVar2;
        param_3[0xd] = (uint)(param_3 + 0x11);
        param_3[0xe] = 3;
        *(undefined1 *)((int)param_3 + 0x46) = (char)param_2;
        *param_3 = (uint)((int)param_3 + 0x46);
        param_3[1] = 1;
      }
      else {
        *param_3 = uVar4 - 1;
        param_3[1] = uVar2 + 1;
      }
      if ((param_3[0x19] & 1) != 0) {
        return uVar5;
      }
LAB_080264ec:
      if (-1 < (int)((uint)(ushort)param_3[3] << 0x16)) {
        FUN_08028654(param_3[0x16]);
        return uVar5;
      }
      return uVar5;
    }
    if (((int)uVar2 < (int)param_3[0xe]) || (iVar1 = FUN_080263c8(param_1,param_3), iVar1 == 0)) {
      uVar2 = *param_3;
      *param_3 = uVar2 - 1;
      *(char *)(uVar2 - 1) = (char)param_2;
      param_3[1] = param_3[1] + 1;
      if ((int)(param_3[0x19] << 0x1f) < 0) {
        return uVar5;
      }
      goto LAB_080264ec;
    }
  }
  else {
    if (-1 < (int)(uVar2 << 0x1b)) {
      if ((int)(param_3[0x19] << 0x1f) < 0) {
        return 0xffffffff;
      }
      goto LAB_08026480;
    }
    if (-1 < (int)(uVar2 << 0x1c)) {
LAB_080264b6:
      *(ushort *)(param_3 + 3) = uVar3 | 4;
      goto LAB_080264bc;
    }
    iVar1 = FUN_08025d30(param_1,param_3);
    if (iVar1 == 0) {
      param_3[2] = 0;
      uVar3 = (ushort)param_3[3] & 0xfff7;
      param_3[6] = 0;
      goto LAB_080264b6;
    }
  }
  if ((int)(param_3[0x19] << 0x1f) < 0) {
    return 0xffffffff;
  }
  uVar2 = (uint)(ushort)param_3[3];
LAB_08026480:
  if ((uVar2 & 0x200) == 0) {
    FUN_08028654(param_3[0x16]);
  }
  return 0xffffffff;
}

