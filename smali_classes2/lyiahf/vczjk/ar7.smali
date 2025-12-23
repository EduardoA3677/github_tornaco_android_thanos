.class public final Llyiahf/vczjk/ar7;
.super Llyiahf/vczjk/cr7;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:I

.field public final OooO0O0:Llyiahf/vczjk/uf5;

.field public final OooO0OO:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/cr7;Llyiahf/vczjk/uf5;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/ar7;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ar7;->OooO0OO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/ar7;->OooO0O0:Llyiahf/vczjk/uf5;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/uf5;Llyiahf/vczjk/jm0;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/ar7;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ar7;->OooO0O0:Llyiahf/vczjk/uf5;

    iput-object p2, p0, Llyiahf/vczjk/ar7;->OooO0OO:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO00o()J
    .locals 2

    iget v0, p0, Llyiahf/vczjk/ar7;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/ar7;->OooO0OO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cr7;

    invoke-virtual {v0}, Llyiahf/vczjk/cr7;->OooO00o()J

    move-result-wide v0

    return-wide v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/ar7;->OooO0OO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/jm0;

    invoke-virtual {v0}, Llyiahf/vczjk/jm0;->OooO0o0()I

    move-result v0

    int-to-long v0, v0

    return-wide v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0O0()Llyiahf/vczjk/uf5;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/ar7;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/ar7;->OooO0O0:Llyiahf/vczjk/uf5;

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/ar7;->OooO0O0:Llyiahf/vczjk/uf5;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0OO(Llyiahf/vczjk/mj0;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/ar7;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/ar7;->OooO0OO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cr7;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/cr7;->OooO0OO(Llyiahf/vczjk/mj0;)V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/ar7;->OooO0OO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/jm0;

    invoke-interface {p1, v0}, Llyiahf/vczjk/mj0;->OooOo0(Llyiahf/vczjk/jm0;)Llyiahf/vczjk/mj0;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
