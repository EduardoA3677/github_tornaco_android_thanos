.class public final synthetic Llyiahf/vczjk/pka;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;II)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/pka;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/pka;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/pka;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/pka;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v1, 0x1

    iget-object v2, p0, Llyiahf/vczjk/pka;->OooOOO:Ljava/lang/Object;

    iget v3, p0, Llyiahf/vczjk/pka;->OooOOO0:I

    packed-switch v3, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget p2, Lgithub/tornaco/practice/honeycomb/locker/ui/setup/WhiteListComponentViewerActivity;->OoooO0O:I

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v2, Lgithub/tornaco/practice/honeycomb/locker/ui/setup/WhiteListComponentViewerActivity;

    invoke-virtual {v2, p2, p1}, Lgithub/tornaco/practice/honeycomb/locker/ui/setup/WhiteListComponentViewerActivity;->OooOoOO(ILlyiahf/vczjk/rf1;)V

    return-object v0

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/dla;

    check-cast p2, Ljava/lang/Boolean;

    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p2

    const-string v3, "wakelock"

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v2, Llyiahf/vczjk/bla;

    invoke-virtual {v2, p1, p2, v1}, Llyiahf/vczjk/bla;->OooOOO0(Llyiahf/vczjk/dla;ZZ)V

    return-object v0

    :pswitch_1
    check-cast p1, Llyiahf/vczjk/b24;

    check-cast p2, Llyiahf/vczjk/b24;

    check-cast v2, Llyiahf/vczjk/uj;

    invoke-virtual {v2}, Llyiahf/vczjk/uj;->OooO0OO()Ljava/lang/Object;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/st;->OooO0O0:Llyiahf/vczjk/st;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    const/16 v1, 0x12c

    const/16 v2, 0x96

    const-wide v3, 0xffffffffL

    const/16 v5, 0x20

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/vj4;

    new-instance v6, Llyiahf/vczjk/uj4;

    invoke-direct {v6}, Llyiahf/vczjk/uj4;-><init>()V

    iget-wide v7, p2, Llyiahf/vczjk/b24;->OooO00o:J

    shr-long/2addr v7, v5

    long-to-int p2, v7

    iget-wide v7, p1, Llyiahf/vczjk/b24;->OooO00o:J

    and-long/2addr v7, v3

    long-to-int p1, v7

    int-to-long v7, p2

    shl-long/2addr v7, v5

    int-to-long p1, p1

    and-long/2addr p1, v3

    or-long/2addr p1, v7

    new-instance v3, Llyiahf/vczjk/b24;

    invoke-direct {v3, p1, p2}, Llyiahf/vczjk/b24;-><init>(J)V

    invoke-virtual {v6, v2, v3}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    iput v1, v6, Llyiahf/vczjk/uj4;->OooO00o:I

    invoke-direct {v0, v6}, Llyiahf/vczjk/vj4;-><init>(Llyiahf/vczjk/uj4;)V

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/vj4;

    new-instance v6, Llyiahf/vczjk/uj4;

    invoke-direct {v6}, Llyiahf/vczjk/uj4;-><init>()V

    iget-wide v7, p1, Llyiahf/vczjk/b24;->OooO00o:J

    shr-long/2addr v7, v5

    long-to-int p1, v7

    iget-wide v7, p2, Llyiahf/vczjk/b24;->OooO00o:J

    and-long/2addr v7, v3

    long-to-int p2, v7

    int-to-long v7, p1

    shl-long/2addr v7, v5

    int-to-long p1, p2

    and-long/2addr p1, v3

    or-long/2addr p1, v7

    new-instance v3, Llyiahf/vczjk/b24;

    invoke-direct {v3, p1, p2}, Llyiahf/vczjk/b24;-><init>(J)V

    invoke-virtual {v6, v2, v3}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    iput v1, v6, Llyiahf/vczjk/uj4;->OooO00o:I

    invoke-direct {v0, v6}, Llyiahf/vczjk/vj4;-><init>(Llyiahf/vczjk/uj4;)V

    :goto_0
    return-object v0

    :pswitch_2
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget p2, Lnow/fortuitous/thanos/power/wakelock/WakeLockBlockerActivity;->OoooO0O:I

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v2, Lnow/fortuitous/thanos/power/wakelock/WakeLockBlockerActivity;

    invoke-virtual {v2, p2, p1}, Lnow/fortuitous/thanos/power/wakelock/WakeLockBlockerActivity;->OooOoOO(ILlyiahf/vczjk/rf1;)V

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
