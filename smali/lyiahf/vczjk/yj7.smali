.class public final Llyiahf/vczjk/yj7;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/zj7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zj7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/yj7;->this$0:Llyiahf/vczjk/zj7;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/yj7;->this$0:Llyiahf/vczjk/zj7;

    const/4 v1, 0x0

    iput-object v1, v0, Llyiahf/vczjk/zj7;->OooO0oO:Llyiahf/vczjk/oO0O00o0;

    const-string v1, "OnPositionedDispatch"

    invoke-static {v1}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    :try_start_0
    invoke-virtual {v0}, Llyiahf/vczjk/zj7;->OooO00o()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-static {}, Landroid/os/Trace;->endSection()V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :catchall_0
    move-exception v0

    invoke-static {}, Landroid/os/Trace;->endSection()V

    throw v0
.end method
