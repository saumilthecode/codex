
char FUN_0801f428(int param_1,undefined4 param_2,int *param_3,int *param_4)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int local_38;
  uint local_34;
  uint local_30;
  int local_2c;
  
  iVar2 = FUN_0801eeba();
  if (iVar2 == 0) {
    uVar6 = param_4[2];
    iVar2 = *(int *)(param_1 + 0xc);
    if ((uVar6 & 0x10) != 0) {
      uVar6 = *(uint *)(param_1 + 8);
    }
    iVar5 = param_1 + iVar2 * 8;
    for (; iVar2 != 0; iVar2 = iVar2 + -1) {
      uVar3 = *(uint *)(iVar5 + 0xc);
      local_38 = 0;
      local_34 = local_34 & 0xffffff00;
      local_2c = 0;
      if ((uVar6 & 1) != 0 || (uVar3 & 2) != 0) {
        if (param_3 == (int *)0x0) {
          iVar4 = 0;
        }
        else {
          iVar4 = (int)uVar3 >> 8;
          if ((uVar3 & 1) != 0) {
            iVar4 = *(int *)(*param_3 + iVar4);
          }
          iVar4 = iVar4 + (int)param_3;
        }
        local_30 = uVar6;
        iVar4 = (**(code **)(**(int **)(iVar5 + 8) + 0x18))
                          (*(int **)(iVar5 + 8),param_2,iVar4,&local_38);
        if (iVar4 != 0) {
          if ((local_2c == 8) && ((uVar3 & 1) != 0)) {
            local_2c = *(int *)(iVar5 + 8);
          }
          if ((3 < (byte)local_34) && ((uVar3 & 2) == 0)) {
            local_34 = local_34 & 0xfffffffd;
          }
          if (param_4[3] != 0) {
            if (*param_4 == local_38) {
              if ((*param_4 != 0) ||
                 (((local_2c != 8 && (param_4[3] != 8)) && (iVar4 = FUN_08008590(), iVar4 != 0)))) {
                *(byte *)(param_4 + 1) = *(byte *)(param_4 + 1) | (byte)local_34;
                goto LAB_0801f496;
              }
            }
            else {
              *param_4 = 0;
            }
            *(undefined1 *)(param_4 + 1) = 2;
            goto LAB_0801f500;
          }
          *param_4 = local_38;
          param_4[1] = local_34;
          param_4[2] = local_30;
          param_4[3] = local_2c;
          uVar3 = (uint)*(byte *)(param_4 + 1);
          if (uVar3 < 4) goto LAB_0801f500;
          if ((int)(uVar3 << 0x1e) < 0) {
            uVar3 = *(uint *)(param_1 + 8) & 1;
          }
          else {
            if (-1 < (int)(uVar3 << 0x1f)) goto LAB_0801f500;
            uVar3 = *(uint *)(param_1 + 8) & 2;
          }
          if (uVar3 == 0) goto LAB_0801f500;
        }
      }
LAB_0801f496:
      iVar5 = iVar5 + -8;
    }
    cVar1 = (char)param_4[1];
    if (cVar1 != '\0') {
      cVar1 = '\x01';
    }
  }
  else {
LAB_0801f500:
    cVar1 = '\x01';
  }
  return cVar1;
}

