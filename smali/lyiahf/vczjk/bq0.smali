.class public final Llyiahf/vczjk/bq0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/mr1;
.implements Llyiahf/vczjk/nr1;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/pp3;

.field public static final OooOOOO:Llyiahf/vczjk/bq0;


# instance fields
.field public final synthetic OooOOO0:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/pp3;

    const/16 v1, 0xd

    invoke-direct {v0, v1}, Llyiahf/vczjk/pp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/bq0;->OooOOO:Llyiahf/vczjk/pp3;

    new-instance v0, Llyiahf/vczjk/bq0;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/bq0;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/bq0;->OooOOOO:Llyiahf/vczjk/bq0;

    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/bq0;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/bq0;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    invoke-static {p0, p1}, Llyiahf/vczjk/tg0;->Oooo000(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object p1

    return-object p1

    :pswitch_0
    invoke-static {p0, p1}, Llyiahf/vczjk/tg0;->Oooo000(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object p1

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/bq0;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    invoke-static {p0, p1}, Llyiahf/vczjk/tg0;->OooOoOO(Llyiahf/vczjk/mr1;Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object p1

    return-object p1

    :pswitch_0
    invoke-static {p0, p1}, Llyiahf/vczjk/tg0;->OooOoOO(Llyiahf/vczjk/mr1;Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object p1

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooOoO(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/or1;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/bq0;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    invoke-static {p0, p1}, Llyiahf/vczjk/tg0;->OooOooO(Llyiahf/vczjk/mr1;Llyiahf/vczjk/nr1;)Llyiahf/vczjk/or1;

    move-result-object p1

    return-object p1

    :pswitch_0
    invoke-static {p0, p1}, Llyiahf/vczjk/tg0;->OooOooO(Llyiahf/vczjk/mr1;Llyiahf/vczjk/nr1;)Llyiahf/vczjk/or1;

    move-result-object p1

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final getKey()Llyiahf/vczjk/nr1;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/bq0;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    return-object p0

    :pswitch_0
    sget-object v0, Llyiahf/vczjk/bq0;->OooOOO:Llyiahf/vczjk/pp3;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final o000OOo(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/bq0;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    invoke-interface {p2, p1, p0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :pswitch_0
    invoke-interface {p2, p1, p0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
