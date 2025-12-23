.class public final Llyiahf/vczjk/nv0;
.super Llyiahf/vczjk/f84;
.source "SourceFile"


# instance fields
.field public final OooOOo:Llyiahf/vczjk/yp0;

.field public final synthetic OooOOo0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/yp0;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/nv0;->OooOOo0:I

    invoke-direct {p0}, Llyiahf/vczjk/r45;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/nv0;->OooOOo:Llyiahf/vczjk/yp0;

    return-void
.end method


# virtual methods
.method public final OooOO0O()Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/nv0;->OooOOo0:I

    packed-switch v0, :pswitch_data_0

    const/4 v0, 0x0

    return v0

    :pswitch_0
    const/4 v0, 0x1

    return v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooOO0o(Ljava/lang/Throwable;)V
    .locals 6

    iget p1, p0, Llyiahf/vczjk/nv0;->OooOOo0:I

    packed-switch p1, :pswitch_data_0

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v0, p0, Llyiahf/vczjk/nv0;->OooOOo:Llyiahf/vczjk/yp0;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    return-void

    :pswitch_0
    invoke-virtual {p0}, Llyiahf/vczjk/f84;->OooOO0()Llyiahf/vczjk/k84;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/nv0;->OooOOo:Llyiahf/vczjk/yp0;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yp0;->OooOOo0(Llyiahf/vczjk/k84;)Ljava/lang/Throwable;

    move-result-object p1

    invoke-virtual {v0}, Llyiahf/vczjk/yp0;->OooOoO0()Z

    move-result v1

    if-nez v1, :cond_0

    goto :goto_1

    :cond_0
    iget-object v1, v0, Llyiahf/vczjk/yp0;->OooOOOo:Llyiahf/vczjk/yo1;

    check-cast v1, Llyiahf/vczjk/fc2;

    :goto_0
    sget-object v2, Llyiahf/vczjk/fc2;->OooOo00:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v2, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/dn8;->OooOOo:Llyiahf/vczjk/h87;

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_3

    :cond_1
    invoke-virtual {v2, v1, v4, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v2, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    if-eq v3, v4, :cond_1

    goto :goto_0

    :cond_3
    instance-of v4, v3, Ljava/lang/Throwable;

    if-eqz v4, :cond_4

    goto :goto_2

    :cond_4
    const/4 v4, 0x0

    invoke-virtual {v2, v1, v3, v4}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_6

    :goto_1
    invoke-virtual {v0, p1}, Llyiahf/vczjk/yp0;->OooOO0o(Ljava/lang/Throwable;)Z

    invoke-virtual {v0}, Llyiahf/vczjk/yp0;->OooOoO0()Z

    move-result p1

    if-nez p1, :cond_5

    invoke-virtual {v0}, Llyiahf/vczjk/yp0;->OooOOO()V

    :cond_5
    :goto_2
    return-void

    :cond_6
    invoke-virtual {v2, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    if-eq v4, v3, :cond_4

    goto :goto_0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
