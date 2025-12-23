.class public final Llyiahf/vczjk/oO00Oo0;
.super Lgithub/tornaco/android/thanos/core/util/AbstractSafeR;
.source "SourceFile"


# instance fields
.field public final synthetic OooOOO0:Llyiahf/vczjk/oO00o000;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oO00o000;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/oO00Oo0;->OooOOO0:Llyiahf/vczjk/oO00o000;

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/core/util/AbstractSafeR;-><init>()V

    return-void
.end method


# virtual methods
.method public final runSafety()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/oO00Oo0;->OooOOO0:Llyiahf/vczjk/oO00o000;

    iget-object v0, v0, Llyiahf/vczjk/l21;->OooOOO:Ljava/lang/Object;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    sget-object v1, Lgithub/tornaco/android/thanos/core/util/ClazzDumper;->ANDROID_UTIL_LOG_PRINTER:Lgithub/tornaco/android/thanos/core/util/ClazzDumper$Printer;

    invoke-static {v0, v1}, Lgithub/tornaco/android/thanos/core/util/ClazzDumper;->dump(Ljava/lang/Class;Lgithub/tornaco/android/thanos/core/util/ClazzDumper$Printer;)V

    return-void
.end method
