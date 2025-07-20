; ModuleID = 'test_ssp_v2.c'
source_filename = "test_ssp_v2.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.anon = type { [16 x i8] }

@result = dso_local global i32 0, align 4

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @test1() #0 {
  %1 = alloca [4 x i8], align 1
  %2 = getelementptr inbounds [4 x i8], [4 x i8]* %1, i64 0, i64 0
  store i8 97, i8* %2, align 1
  %3 = getelementptr inbounds [4 x i8], [4 x i8]* %1, i64 0, i64 0
  %4 = load i8, i8* %3, align 1
  %5 = sext i8 %4 to i32
  store volatile i32 %5, i32* @result, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @test2() #0 {
  %1 = alloca [16 x i8], align 16
  %2 = getelementptr inbounds [16 x i8], [16 x i8]* %1, i64 0, i64 0
  store i8 97, i8* %2, align 16
  %3 = getelementptr inbounds [16 x i8], [16 x i8]* %1, i64 0, i64 0
  %4 = load i8, i8* %3, align 16
  %5 = sext i8 %4 to i32
  store volatile i32 %5, i32* @result, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @test3() #0 {
  %1 = alloca [4 x i8], align 1
  %2 = getelementptr inbounds [4 x i8], [4 x i8]* %1, i64 0, i64 0
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 4, i1 false)
  %3 = getelementptr inbounds [4 x i8], [4 x i8]* %1, i64 0, i64 0
  %4 = load i8, i8* %3, align 1
  %5 = sext i8 %4 to i32
  store volatile i32 %5, i32* @result, align 4
  ret void
}

; Function Attrs: argmemonly nofree nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1 immarg) #1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @test4() #0 {
  %1 = alloca [16 x i8], align 16
  %2 = getelementptr inbounds [16 x i8], [16 x i8]* %1, i64 0, i64 0
  call void @llvm.memset.p0i8.i64(i8* align 16 %2, i8 0, i64 16, i1 false)
  %3 = getelementptr inbounds [16 x i8], [16 x i8]* %1, i64 0, i64 0
  %4 = load i8, i8* %3, align 16
  %5 = sext i8 %4 to i32
  store volatile i32 %5, i32* @result, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @test5() #0 {
  %1 = alloca %struct.anon, align 1
  %2 = bitcast %struct.anon* %1 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 16, i1 false)
  %3 = getelementptr inbounds %struct.anon, %struct.anon* %1, i32 0, i32 0
  %4 = getelementptr inbounds [16 x i8], [16 x i8]* %3, i64 0, i64 0
  %5 = load i8, i8* %4, align 1
  %6 = sext i8 %5 to i32
  store volatile i32 %6, i32* @result, align 4
  ret void
}

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { argmemonly nofree nounwind willreturn writeonly }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 7, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 1}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"Ubuntu clang version 14.0.0-1ubuntu1.1"}
