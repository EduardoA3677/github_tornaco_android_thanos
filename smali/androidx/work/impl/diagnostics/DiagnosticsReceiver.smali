.class public Landroidx/work/impl/diagnostics/DiagnosticsReceiver;
.super Landroid/content/BroadcastReceiver;
.source "SourceFile"


# static fields
.field public static final OooO00o:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "DiagnosticsRcvr"

    invoke-static {v0}, Llyiahf/vczjk/o55;->OooOOOO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    sput-object v0, Landroidx/work/impl/diagnostics/DiagnosticsReceiver;->OooO00o:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    return-void
.end method


# virtual methods
.method public final onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 3

    if-nez p2, :cond_0

    goto :goto_0

    :cond_0
    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p2

    sget-object v0, Landroidx/work/impl/diagnostics/DiagnosticsReceiver;->OooO00o:Ljava/lang/String;

    const-string v1, "Requesting diagnostics"

    invoke-virtual {p2, v0, v1}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    :try_start_0
    const-string p2, "context"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/oqa;->OoooOoo(Landroid/content/Context;)Llyiahf/vczjk/oqa;

    move-result-object p1

    const-class p2, Landroidx/work/impl/workers/DiagnosticsWorker;

    new-instance v1, Llyiahf/vczjk/sb6;

    const/4 v2, 0x0

    invoke-direct {v1, v2, p2}, Llyiahf/vczjk/sb6;-><init>(ILjava/lang/Class;)V

    invoke-virtual {v1}, Llyiahf/vczjk/yd7;->OooO0O0()Llyiahf/vczjk/yqa;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/tb6;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/nqa;->OooOo0(Llyiahf/vczjk/yqa;)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p1

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p2

    const-string v1, "WorkManager is not initialized"

    invoke-virtual {p2, v0, v1, p1}, Llyiahf/vczjk/o55;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    :goto_0
    return-void
.end method
