
undefined4 FUN_08007e08(char *param_1,int *param_2,undefined4 param_3,undefined4 *param_4)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  undefined4 uVar4;
  char *pcVar5;
  int *local_1c;
  
  cVar1 = param_1[7];
  pcVar5 = param_1;
  if (((((*param_1 == 'G') && (param_1[1] == 'N')) && (param_1[2] == 'U')) &&
      ((param_1[3] == 'C' && (param_1[4] == 'F')))) &&
     ((param_1[5] == 'O' && ((param_1[6] == 'R' && (cVar1 == '\0')))))) {
    piVar3 = DAT_08007ea8;
    local_1c = (int *)0x0;
  }
  else {
    local_1c = param_2;
    iVar2 = FUN_08007dce(param_1);
    local_1c = (int *)0x0;
    piVar3 = DAT_08007ea4;
    if (iVar2 != 0) {
      local_1c = *(int **)(param_1 + -0x20);
      if (cVar1 == '\x01') {
        piVar3 = (int *)local_1c[-0x1e];
      }
      else {
        piVar3 = local_1c;
        local_1c = (int *)(param_1 + 0x58);
      }
    }
  }
  iVar2 = (**(code **)(*piVar3 + 8))(piVar3);
  if (iVar2 == 0) {
    uVar4 = 1;
  }
  else {
    local_1c = (int *)*local_1c;
    uVar4 = 2;
  }
  iVar2 = (**(code **)(*param_2 + 0x10))(param_2,piVar3,&local_1c,1,pcVar5);
  if (iVar2 == 0) {
    uVar4 = 0;
  }
  else {
    *param_4 = local_1c;
  }
  return uVar4;
}

