.class public final Llyiahf/vczjk/fd2;
.super Llyiahf/vczjk/o0OOO0o;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:I

.field public final OooO0O0:Llyiahf/vczjk/gd0;


# direct methods
.method public constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/fd2;->OooO00o:I

    packed-switch p1, :pswitch_data_0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Llyiahf/vczjk/ed2;

    invoke-direct {p1}, Llyiahf/vczjk/ak1;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fd2;->OooO0O0:Llyiahf/vczjk/gd0;

    return-void

    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Llyiahf/vczjk/cq9;

    invoke-direct {p1}, Llyiahf/vczjk/ak1;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fd2;->OooO0O0:Llyiahf/vczjk/gd0;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method private final OooO(Ljava/lang/CharSequence;)V
    .locals 0

    return-void
.end method


# virtual methods
.method public OooO00o(Ljava/lang/CharSequence;)V
    .locals 0

    iget p1, p0, Llyiahf/vczjk/fd2;->OooO00o:I

    return-void
.end method

.method public OooO0O0(Llyiahf/vczjk/gd0;)Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/fd2;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0, p1}, Llyiahf/vczjk/o0OOO0o;->OooO0O0(Llyiahf/vczjk/gd0;)Z

    move-result p1

    return p1

    :pswitch_0
    const/4 p1, 0x1

    return p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public OooO0o()Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/fd2;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0}, Llyiahf/vczjk/o0OOO0o;->OooO0o()Z

    move-result v0

    return v0

    :pswitch_0
    const/4 v0, 0x1

    return v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0o0()Llyiahf/vczjk/gd0;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/fd2;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/fd2;->OooO0O0:Llyiahf/vczjk/gd0;

    check-cast v0, Llyiahf/vczjk/cq9;

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/fd2;->OooO0O0:Llyiahf/vczjk/gd0;

    check-cast v0, Llyiahf/vczjk/ed2;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0oo(Llyiahf/vczjk/md2;)Llyiahf/vczjk/hd0;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/fd2;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    const/4 p1, 0x0

    return-object p1

    :pswitch_0
    iget p1, p1, Llyiahf/vczjk/md2;->OooO0O0:I

    invoke-static {p1}, Llyiahf/vczjk/hd0;->OooO00o(I)Llyiahf/vczjk/hd0;

    move-result-object p1

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
