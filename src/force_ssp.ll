; ModuleID = 'force_ssp.c'
source_filename = "force_ssp.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [41 x i8] c"this is a long string that will overflow\00", align 1

; Function Attrs: noinline nounwind optnone sspreq uwtable
define dso_local void @vulnerable_func(i8* noundef %0) #0 {
  %2 = alloca i8*, align 8
  %3 = alloca [8 x i8], align 1
  store i8* %0, i8** %2, align 8
  %4 = getelementptr inbounds [8 x i8], [8 x i8]* %3, i64 0, i64 0
  %5 = load i8*, i8** %2, align 8
  %6 = call i8* @strcpy(i8* noundef %4, i8* noundef %5) #2
  ret void
}

; Function Attrs: nounwind
declare i8* @strcpy(i8* noundef, i8* noundef) #1

; Function Attrs: noinline nounwind optnone sspreq uwtable
define dso_local void @test_overflow() #0 {
  call void @vulnerable_func(i8* noundef getelementptr inbounds ([41 x i8], [41 x i8]* @.str, i64 0, i64 0))
  ret void
}

attributes #0 = { noinline nounwind optnone sspreq uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nounwind "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { nounwind }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 7, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 1}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"Ubuntu clang version 14.0.0-1ubuntu1.1"}
