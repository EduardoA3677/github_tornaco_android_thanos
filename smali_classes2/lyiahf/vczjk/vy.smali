.class public final Llyiahf/vczjk/vy;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/wf8;


# instance fields
.field public final synthetic OooO00o:I

.field public final OooO0O0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/vy;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/vy;->OooO0O0:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ze3;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Llyiahf/vczjk/vy;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    check-cast p1, Llyiahf/vczjk/rs7;

    iput-object p1, p0, Llyiahf/vczjk/vy;->OooO0O0:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final iterator()Ljava/util/Iterator;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/vy;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/zz4;

    iget-object v1, p0, Llyiahf/vczjk/vy;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Ljava/lang/String;

    invoke-direct {v0, v1}, Llyiahf/vczjk/zz4;-><init>(Ljava/lang/String;)V

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/vy;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Ljava/util/Iterator;

    return-object v0

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/vy;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/rs7;

    invoke-static {v0}, Llyiahf/vczjk/vl6;->OooOo0(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/xf8;

    move-result-object v0

    return-object v0

    :pswitch_2
    new-instance v0, Llyiahf/vczjk/a05;

    invoke-direct {v0, p0}, Llyiahf/vczjk/a05;-><init>(Llyiahf/vczjk/vy;)V

    return-object v0

    :pswitch_3
    iget-object v0, p0, Llyiahf/vczjk/vy;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Ljava/lang/Iterable;

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    return-object v0

    :pswitch_4
    iget-object v0, p0, Llyiahf/vczjk/vy;->OooO0O0:Ljava/lang/Object;

    check-cast v0, [Ljava/lang/Object;

    invoke-static {v0}, Llyiahf/vczjk/bua;->OooOooo([Ljava/lang/Object;)Llyiahf/vczjk/o00O000;

    move-result-object v0

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
