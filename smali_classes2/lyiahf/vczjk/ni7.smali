.class public final Llyiahf/vczjk/ni7;
.super Llyiahf/vczjk/ks7;
.source "SourceFile"


# instance fields
.field public final synthetic OooOOO:I

.field public final OooOOOO:J

.field public final OooOOOo:Ljava/lang/Object;

.field public final OooOOo0:Llyiahf/vczjk/nj0;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;JLlyiahf/vczjk/nj0;I)V
    .locals 0

    iput p5, p0, Llyiahf/vczjk/ni7;->OooOOO:I

    iput-object p1, p0, Llyiahf/vczjk/ni7;->OooOOOo:Ljava/lang/Object;

    iput-wide p2, p0, Llyiahf/vczjk/ni7;->OooOOOO:J

    iput-object p4, p0, Llyiahf/vczjk/ni7;->OooOOo0:Llyiahf/vczjk/nj0;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0Oo()J
    .locals 2

    iget v0, p0, Llyiahf/vczjk/ni7;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    iget-wide v0, p0, Llyiahf/vczjk/ni7;->OooOOOO:J

    return-wide v0

    :pswitch_0
    iget-wide v0, p0, Llyiahf/vczjk/ni7;->OooOOOO:J

    return-wide v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0oO()Llyiahf/vczjk/uf5;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ni7;->OooOOOo:Ljava/lang/Object;

    iget v1, p0, Llyiahf/vczjk/ni7;->OooOOO:I

    packed-switch v1, :pswitch_data_0

    check-cast v0, Llyiahf/vczjk/uf5;

    return-object v0

    :pswitch_0
    const/4 v1, 0x0

    check-cast v0, Ljava/lang/String;

    if-eqz v0, :cond_0

    sget-object v2, Llyiahf/vczjk/uf5;->OooO0Oo:Ljava/util/regex/Pattern;

    :try_start_0
    invoke-static {v0}, Llyiahf/vczjk/zsa;->OoooO00(Ljava/lang/String;)Llyiahf/vczjk/uf5;

    move-result-object v1
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    :cond_0
    return-object v1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooOOOO()Llyiahf/vczjk/nj0;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/ni7;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/ni7;->OooOOo0:Llyiahf/vczjk/nj0;

    check-cast v0, Llyiahf/vczjk/yi0;

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/ni7;->OooOOo0:Llyiahf/vczjk/nj0;

    check-cast v0, Llyiahf/vczjk/ih7;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
