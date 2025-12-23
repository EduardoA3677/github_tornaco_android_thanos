.class public final Llyiahf/vczjk/cs6;
.super Llyiahf/vczjk/qr1;
.source "SourceFile"


# instance fields
.field public final OooOOOO:Llyiahf/vczjk/ec2;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/qr1;-><init>()V

    new-instance v0, Llyiahf/vczjk/ec2;

    invoke-direct {v0}, Llyiahf/vczjk/ec2;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/cs6;->OooOOOO:Llyiahf/vczjk/ec2;

    return-void
.end method


# virtual methods
.method public final o00000o0(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V
    .locals 4

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "block"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/cs6;->OooOOOO:Llyiahf/vczjk/ec2;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v1, Llyiahf/vczjk/y95;->OooO00o:Llyiahf/vczjk/xl3;

    iget-object v1, v1, Llyiahf/vczjk/xl3;->OooOOo:Llyiahf/vczjk/xl3;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/xl3;->o00000oO(Llyiahf/vczjk/or1;)Z

    move-result v2

    if-nez v2, :cond_4

    iget-boolean v2, v0, Llyiahf/vczjk/ec2;->OooOOO:Z

    if-nez v2, :cond_1

    iget-boolean v2, v0, Llyiahf/vczjk/ec2;->OooOOO0:Z

    if-nez v2, :cond_0

    goto :goto_0

    :cond_0
    const/4 v2, 0x0

    goto :goto_1

    :cond_1
    :goto_0
    const/4 v2, 0x1

    :goto_1
    if-eqz v2, :cond_2

    goto :goto_2

    :cond_2
    iget-object p1, v0, Llyiahf/vczjk/ec2;->OooOOOo:Ljava/lang/Object;

    check-cast p1, Ljava/util/ArrayDeque;

    invoke-virtual {p1, p2}, Ljava/util/ArrayDeque;->offer(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_3

    invoke-virtual {v0}, Llyiahf/vczjk/ec2;->OooO00o()V

    return-void

    :cond_3
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "cannot enqueue any more runnables"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_4
    :goto_2
    new-instance v2, Llyiahf/vczjk/oO0oO000;

    const/16 v3, 0x1a

    invoke-direct {v2, v3, v0, p2}, Llyiahf/vczjk/oO0oO000;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v1, p1, v2}, Llyiahf/vczjk/xl3;->o00000o0(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V

    return-void
.end method

.method public final o00000oO(Llyiahf/vczjk/or1;)Z
    .locals 2

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v0, Llyiahf/vczjk/y95;->OooO00o:Llyiahf/vczjk/xl3;

    iget-object v0, v0, Llyiahf/vczjk/xl3;->OooOOo:Llyiahf/vczjk/xl3;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/xl3;->o00000oO(Llyiahf/vczjk/or1;)Z

    move-result p1

    const/4 v0, 0x1

    if-eqz p1, :cond_0

    return v0

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/cs6;->OooOOOO:Llyiahf/vczjk/ec2;

    iget-boolean v1, p1, Llyiahf/vczjk/ec2;->OooOOO:Z

    if-nez v1, :cond_2

    iget-boolean p1, p1, Llyiahf/vczjk/ec2;->OooOOO0:Z

    if-nez p1, :cond_1

    goto :goto_0

    :cond_1
    const/4 p1, 0x0

    goto :goto_1

    :cond_2
    :goto_0
    move p1, v0

    :goto_1
    xor-int/2addr p1, v0

    return p1
.end method
