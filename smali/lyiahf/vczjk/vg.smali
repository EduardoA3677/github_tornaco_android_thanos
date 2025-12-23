.class public final Llyiahf/vczjk/vg;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/view/Choreographer$FrameCallback;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOO0:Llyiahf/vczjk/yp0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yp0;Llyiahf/vczjk/wg;Llyiahf/vczjk/oe3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/vg;->OooOOO0:Llyiahf/vczjk/yp0;

    iput-object p3, p0, Llyiahf/vczjk/vg;->OooOOO:Llyiahf/vczjk/oe3;

    return-void
.end method


# virtual methods
.method public final doFrame(J)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vg;->OooOOO:Llyiahf/vczjk/oe3;

    :try_start_0
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p1

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p1

    :goto_0
    iget-object p2, p0, Llyiahf/vczjk/vg;->OooOOO0:Llyiahf/vczjk/yp0;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    return-void
.end method
