
void FUN_0801f588(char *param_1,char *param_2,undefined4 *param_3)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 uVar4;
  char *local_1c;
  
  local_1c = param_2;
  iVar1 = FUN_0801f54c();
  if (iVar1 == 0) {
    *param_3 = 4;
    return;
  }
  uVar2 = FUN_08025738(param_1,&local_1c);
  *(undefined4 *)param_2 = uVar2;
  if ((local_1c == param_1) || (*local_1c != '\0')) {
    uVar4 = 0;
  }
  else {
    iVar3 = FUN_080068f0(uVar2,0x7f800000);
    uVar4 = DAT_0801f5f8;
    if (iVar3 == 0) {
      iVar3 = FUN_080068f0(uVar2,DAT_0801f5f4);
      if (iVar3 == 0) goto LAB_0801f5c2;
      uVar4 = 0xff7fffff;
    }
  }
  *(undefined4 *)param_2 = uVar4;
  *param_3 = 4;
LAB_0801f5c2:
  FUN_08028514(0,iVar1);
  thunk_FUN_080249c4(iVar1);
  return;
}

