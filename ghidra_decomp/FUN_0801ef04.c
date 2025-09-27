
int FUN_0801ef04(int *param_1,undefined4 param_2,int *param_3,int param_4)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  bool bVar5;
  int local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  if (param_1 != (int *)0x0) {
    iVar3 = *(int *)(*param_1 + -8);
    piVar4 = *(int **)(*param_1 + -4);
    local_2c = 0;
    local_28 = 0;
    local_24 = 0x10;
    if (*(int **)(*(int *)((int)param_1 + iVar3) + -4) == piVar4) {
      if (((-1 < param_4) && (param_4 + iVar3 == 0)) &&
         (iVar1 = FUN_08008590(piVar4,param_3), iVar1 != 0)) {
        return (int)param_1 + iVar3;
      }
      (**(code **)(*piVar4 + 0x1c))
                (piVar4,param_4,6,param_3,(int)param_1 + iVar3,param_2,param_1,&local_2c);
      if (local_2c != 0) {
        if ((local_28._2_1_ & 6) == 6) {
          return local_2c;
        }
        if (((byte)local_28 & local_28._1_1_ & 6) == 6) {
          return local_2c;
        }
        if (((local_28._1_1_ & 5) != 4) && (local_28._2_1_ == 0)) {
          if (param_4 < 0) {
            if (param_4 == -2) {
              return 0;
            }
            uVar2 = (**(code **)(*param_3 + 0x20))(param_3,param_4,local_2c,param_2,param_1);
            bVar5 = (uVar2 & 6) == 6;
          }
          else {
            bVar5 = param_1 == (int *)(local_2c + param_4);
          }
          if (bVar5) {
            return local_2c;
          }
        }
      }
    }
  }
  return 0;
}

