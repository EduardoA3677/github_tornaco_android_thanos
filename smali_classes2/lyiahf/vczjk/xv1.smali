.class public final Llyiahf/vczjk/xv1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le7;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/wv1;

.field public final OooO0O0:Llyiahf/vczjk/yv1;

.field public final OooO0OO:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wv1;Llyiahf/vczjk/yv1;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/xv1;->OooO00o:Llyiahf/vczjk/wv1;

    iput-object p2, p0, Llyiahf/vczjk/xv1;->OooO0O0:Llyiahf/vczjk/yv1;

    iput p3, p0, Llyiahf/vczjk/xv1;->OooO0OO:I

    return-void
.end method


# virtual methods
.method public final get()Ljava/lang/Object;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/xv1;->OooO0O0:Llyiahf/vczjk/yv1;

    iget-object v1, p0, Llyiahf/vczjk/xv1;->OooO00o:Llyiahf/vczjk/wv1;

    iget v2, p0, Llyiahf/vczjk/xv1;->OooO0OO:I

    packed-switch v2, :pswitch_data_0

    new-instance v0, Ljava/lang/AssertionError;

    invoke-direct {v0, v2}, Ljava/lang/AssertionError;-><init>(I)V

    throw v0

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/bla;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/bla;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_1
    new-instance v0, Llyiahf/vczjk/mka;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/mka;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_2
    new-instance v0, Llyiahf/vczjk/v89;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/v89;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_3
    new-instance v0, Llyiahf/vczjk/w39;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/w39;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_4
    new-instance v0, Llyiahf/vczjk/n19;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/n19;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_5
    new-instance v0, Llyiahf/vczjk/vm8;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/vm8;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_6
    new-instance v0, Llyiahf/vczjk/cj8;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/cj8;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_7
    new-instance v0, Llyiahf/vczjk/dj8;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/dj8;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_8
    new-instance v0, Llyiahf/vczjk/dh8;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/t81;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_9
    new-instance v2, Llyiahf/vczjk/h48;

    iget-object v3, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v3, v3, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    iget-object v0, v0, Llyiahf/vczjk/yv1;->OooO00o:Llyiahf/vczjk/x58;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO0o:Llyiahf/vczjk/le7;

    invoke-interface {v1}, Llyiahf/vczjk/le7;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/e28;

    invoke-direct {v2, v3, v0, v1}, Llyiahf/vczjk/h48;-><init>(Landroid/content/Context;Llyiahf/vczjk/x58;Llyiahf/vczjk/e28;)V

    return-object v2

    :pswitch_a
    new-instance v2, Llyiahf/vczjk/i48;

    iget-object v3, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v3, v3, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    iget-object v0, v0, Llyiahf/vczjk/yv1;->OooO00o:Llyiahf/vczjk/x58;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO0oO:Llyiahf/vczjk/le7;

    invoke-interface {v1}, Llyiahf/vczjk/le7;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/f28;

    invoke-direct {v2, v3, v0, v1}, Llyiahf/vczjk/i48;-><init>(Landroid/content/Context;Llyiahf/vczjk/x58;Llyiahf/vczjk/f28;)V

    return-object v2

    :pswitch_b
    new-instance v0, Llyiahf/vczjk/ny7;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/ny7;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_c
    new-instance v0, Llyiahf/vczjk/oy7;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/oy7;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_d
    new-instance v0, Llyiahf/vczjk/wi7;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/t81;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_e
    new-instance v0, Llyiahf/vczjk/me7;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/t81;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_f
    new-instance v0, Llyiahf/vczjk/g87;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/g87;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_10
    new-instance v0, Llyiahf/vczjk/k77;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/k77;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_11
    new-instance v0, Llyiahf/vczjk/a77;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/a77;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_12
    new-instance v2, Llyiahf/vczjk/gw6;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    iget-object v0, v0, Llyiahf/vczjk/yv1;->OooO00o:Llyiahf/vczjk/x58;

    invoke-direct {v2, v1, v0}, Llyiahf/vczjk/gw6;-><init>(Landroid/content/Context;Llyiahf/vczjk/x58;)V

    return-object v2

    :pswitch_13
    new-instance v0, Llyiahf/vczjk/pu6;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/pu6;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_14
    new-instance v0, Llyiahf/vczjk/vr6;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/vr6;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_15
    new-instance v0, Llyiahf/vczjk/cf6;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/cf6;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_16
    new-instance v2, Llyiahf/vczjk/nc6;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    new-instance v3, Llyiahf/vczjk/ec6;

    iget-object v0, v0, Llyiahf/vczjk/yv1;->OooO0O0:Llyiahf/vczjk/wv1;

    iget-object v0, v0, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v0, v0, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v3, v0}, Llyiahf/vczjk/ec6;-><init>(Landroid/content/Context;)V

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/nc6;-><init>(Landroid/content/Context;Llyiahf/vczjk/ec6;)V

    return-object v2

    :pswitch_17
    new-instance v0, Llyiahf/vczjk/vw5;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/vw5;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_18
    new-instance v0, Llyiahf/vczjk/ua5;

    iget-object v2, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v2, v2, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    iget-object v3, v1, Llyiahf/vczjk/wv1;->OooO0o:Llyiahf/vczjk/le7;

    invoke-interface {v3}, Llyiahf/vczjk/le7;->get()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/e28;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO0Oo:Llyiahf/vczjk/le7;

    invoke-interface {v1}, Llyiahf/vczjk/le7;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/o30;

    invoke-direct {v0, v2, v3, v1}, Llyiahf/vczjk/ua5;-><init>(Landroid/content/Context;Llyiahf/vczjk/e28;Llyiahf/vczjk/o30;)V

    return-object v0

    :pswitch_19
    new-instance v0, Llyiahf/vczjk/l55;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/l55;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_1a
    new-instance v0, Llyiahf/vczjk/on4;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/on4;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_1b
    new-instance v0, Llyiahf/vczjk/k02;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/k02;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_1c
    new-instance v0, Llyiahf/vczjk/lw1;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/lw1;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_1d
    new-instance v0, Llyiahf/vczjk/fj1;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/fj1;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_1e
    new-instance v2, Llyiahf/vczjk/l71;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    iget-object v0, v0, Llyiahf/vczjk/yv1;->OooO00o:Llyiahf/vczjk/x58;

    const-string v1, "savedStateHandle"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v2}, Llyiahf/vczjk/fy4;-><init>()V

    new-instance v1, Lgithub/tornaco/android/thanos/core/Logger;

    const-string v3, "ComponentVM"

    invoke-direct {v1, v3}, Lgithub/tornaco/android/thanos/core/Logger;-><init>(Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/h71;

    invoke-direct {v1}, Llyiahf/vczjk/h71;-><init>()V

    invoke-static {v1}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object v1

    new-instance v3, Llyiahf/vczjk/gh7;

    invoke-direct {v3, v1}, Llyiahf/vczjk/gh7;-><init>(Llyiahf/vczjk/rs5;)V

    const-string v1, "query"

    const-string v4, ""

    invoke-virtual {v0, v1, v4}, Llyiahf/vczjk/x58;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/gh7;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/b40;

    const/4 v4, 0x3

    invoke-direct {v1, v3, v4}, Llyiahf/vczjk/b40;-><init>(Llyiahf/vczjk/gh7;I)V

    new-instance v3, Llyiahf/vczjk/i71;

    const/4 v4, 0x3

    const/4 v5, 0x0

    invoke-direct {v3, v4, v5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    new-instance v4, Llyiahf/vczjk/y63;

    invoke-direct {v4, v1, v0, v3}, Llyiahf/vczjk/y63;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/f43;Llyiahf/vczjk/bf3;)V

    invoke-static {v2}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/ql8;->OooO0O0:Llyiahf/vczjk/e86;

    sget-object v3, Llyiahf/vczjk/q7a;->OooO00o:Llyiahf/vczjk/q7a;

    invoke-static {v4, v0, v1, v3}, Llyiahf/vczjk/rs;->OoooOoo(Llyiahf/vczjk/f43;Llyiahf/vczjk/xr1;Llyiahf/vczjk/rl8;Ljava/lang/Object;)Llyiahf/vczjk/gh7;

    return-object v2

    :pswitch_1f
    new-instance v0, Llyiahf/vczjk/g70;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/g70;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_20
    new-instance v2, Llyiahf/vczjk/i40;

    iget-object v0, v0, Llyiahf/vczjk/yv1;->OooO00o:Llyiahf/vczjk/x58;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO0Oo:Llyiahf/vczjk/le7;

    invoke-interface {v1}, Llyiahf/vczjk/le7;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/o30;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/i40;-><init>(Llyiahf/vczjk/x58;Llyiahf/vczjk/o30;)V

    return-object v2

    :pswitch_21
    new-instance v0, Llyiahf/vczjk/aw;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/aw;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_22
    new-instance v0, Llyiahf/vczjk/dv;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/dv;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_23
    new-instance v0, Llyiahf/vczjk/w6;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/w6;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_24
    new-instance v0, Llyiahf/vczjk/oOo00o0o;

    iget-object v1, v1, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v1, v1, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/t81;-><init>(Landroid/content/Context;)V

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
