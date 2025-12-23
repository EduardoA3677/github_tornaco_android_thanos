.class public final Llyiahf/vczjk/n3;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/oe3;

.field public final OooO0O0:Llyiahf/vczjk/qs5;

.field public OooO0OO:Ljava/time/LocalTime;

.field public final OooO0Oo:Llyiahf/vczjk/qs5;

.field public final OooO0o0:Llyiahf/vczjk/qs5;


# direct methods
.method public constructor <init>(Ljava/time/LocalTime;[Lgithub/tornaco/android/thanos/core/alarm/WeekDay;Llyiahf/vczjk/oe3;)V
    .locals 1

    const-string v0, "initialTime"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p3, p0, Llyiahf/vczjk/n3;->OooO00o:Llyiahf/vczjk/oe3;

    sget-object p3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {p3}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p3

    iput-object p3, p0, Llyiahf/vczjk/n3;->OooO0O0:Llyiahf/vczjk/qs5;

    iput-object p1, p0, Llyiahf/vczjk/n3;->OooO0OO:Ljava/time/LocalTime;

    invoke-static {p2}, Llyiahf/vczjk/sy;->o0000oO([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/n3;->OooO0Oo:Llyiahf/vczjk/qs5;

    const-string p1, ""

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/n3;->OooO0o0:Llyiahf/vczjk/qs5;

    return-void
.end method
