.class public final Llyiahf/vczjk/uy2;
.super Landroid/os/FileObserver;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/vy2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/vy2;Ljava/lang/String;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/uy2;->OooO00o:Llyiahf/vczjk/vy2;

    const/16 p1, 0x3c0

    invoke-direct {p0, p2, p1}, Landroid/os/FileObserver;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final onEvent(ILjava/lang/String;)V
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/uy2;->OooO00o:Llyiahf/vczjk/vy2;

    iget-boolean p2, p1, Llyiahf/vczjk/vy2;->OooO0O0:Z

    if-eqz p2, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/vy2;->OooO00o()V

    new-instance p2, Llyiahf/vczjk/w00;

    invoke-direct {p2, p1}, Llyiahf/vczjk/w00;-><init>(Llyiahf/vczjk/vy2;)V

    iput-object p2, p1, Llyiahf/vczjk/vy2;->OooO0oO:Llyiahf/vczjk/w00;

    invoke-virtual {p1}, Llyiahf/vczjk/vy2;->OooO0O0()V

    return-void

    :cond_0
    const/4 p2, 0x1

    iput-boolean p2, p1, Llyiahf/vczjk/vy2;->OooO0o0:Z

    return-void
.end method
