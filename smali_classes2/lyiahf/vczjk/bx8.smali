.class public final Llyiahf/vczjk/bx8;
.super Llyiahf/vczjk/o00O00o0;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/bx8;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public OooO0oO(Llyiahf/vczjk/ld9;)V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/bx8;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    return-void

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/h69;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/h69;-><init>(I)V

    invoke-static {v0}, Ljava/util/Collections;->singleton(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ld9;->Oooo0oo(Ljava/lang/Iterable;)V

    return-void

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public OooO0oo(Llyiahf/vczjk/tg7;)V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/bx8;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    return-void

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/qd0;

    const/16 v1, 0x8

    invoke-direct {v0, v1}, Llyiahf/vczjk/qd0;-><init>(I)V

    const-class v1, Llyiahf/vczjk/f69;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tg7;->Oooo00o(Ljava/lang/Class;Llyiahf/vczjk/cy8;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public final OooOO0(Llyiahf/vczjk/tqa;)V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/bx8;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/xc9;

    const/16 v1, 0x11

    invoke-direct {v0, v1}, Llyiahf/vczjk/xc9;-><init>(I)V

    const-class v1, Llyiahf/vczjk/f69;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    return-void

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/xc9;

    const/16 v1, 0x10

    invoke-direct {v0, v1}, Llyiahf/vczjk/xc9;-><init>(I)V

    const-class v1, Llyiahf/vczjk/cx8;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
