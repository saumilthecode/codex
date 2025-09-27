
bool FUN_08007dc2(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  char *pcVar2;
  
  uVar1 = FUN_08007ee6();
  pcVar2 = (char *)FUN_08006acc(uVar1,param_2,param_3,param_4);
  if ((((*pcVar2 == 'G') && (pcVar2[1] == 'N')) && (pcVar2[2] == 'U')) &&
     (((pcVar2[3] == 'C' && (pcVar2[4] == 'C')) && ((pcVar2[5] == '+' && (pcVar2[6] == '+')))))) {
    return (byte)pcVar2[7] < 2;
  }
  return false;
}

