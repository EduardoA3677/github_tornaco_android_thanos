.class public final Llyiahf/vczjk/o0OO00O;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/oo0o0Oo;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/oo0o0Oo;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/o0OO00O;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/o0OO00O;->OooOOO:Llyiahf/vczjk/oo0o0Oo;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/o0OO00O;->OooOOO:Llyiahf/vczjk/oo0o0Oo;

    iget v1, p0, Llyiahf/vczjk/o0OO00O;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    new-instance v1, Llyiahf/vczjk/mp4;

    invoke-direct {v1, v0}, Llyiahf/vczjk/mp4;-><init>(Llyiahf/vczjk/by0;)V

    return-object v1

    :pswitch_0
    new-instance v1, Llyiahf/vczjk/zz3;

    invoke-virtual {v0}, Llyiahf/vczjk/oo0o0Oo;->o0OO00O()Llyiahf/vczjk/jg5;

    move-result-object v0

    invoke-direct {v1, v0}, Llyiahf/vczjk/zz3;-><init>(Llyiahf/vczjk/jg5;)V

    return-object v1

    :pswitch_1
    invoke-virtual {v0}, Llyiahf/vczjk/oo0o0Oo;->o0OO00O()Llyiahf/vczjk/jg5;

    move-result-object v6

    new-instance v7, Llyiahf/vczjk/oo000o;

    const/4 v1, 0x1

    invoke-direct {v7, p0, v1}, Llyiahf/vczjk/oo000o;-><init>(Ljava/lang/Object;I)V

    sget-object v1, Llyiahf/vczjk/l5a;->OooO00o:Llyiahf/vczjk/rq2;

    invoke-static {v0}, Llyiahf/vczjk/uq2;->OooO0o(Llyiahf/vczjk/v02;)Z

    move-result v1

    if-eqz v1, :cond_0

    sget-object v1, Llyiahf/vczjk/tq2;->OooOo0:Llyiahf/vczjk/tq2;

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    filled-new-array {v0}, [Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0}, Llyiahf/vczjk/uq2;->OooO0OO(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/rq2;

    move-result-object v0

    goto :goto_0

    :cond_0
    invoke-interface {v0}, Llyiahf/vczjk/gz0;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v3

    const/4 v0, 0x0

    if-eqz v3, :cond_2

    if-eqz v6, :cond_1

    invoke-interface {v3}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/l5a;->OooO0Oo(Ljava/util/List;)Ljava/util/List;

    move-result-object v4

    sget-object v0, Llyiahf/vczjk/d3a;->OooOOO:Llyiahf/vczjk/xo8;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v2, Llyiahf/vczjk/d3a;->OooOOOO:Llyiahf/vczjk/d3a;

    const/4 v5, 0x0

    invoke-static/range {v2 .. v7}, Llyiahf/vczjk/so8;->Oooo(Llyiahf/vczjk/d3a;Llyiahf/vczjk/n3a;Ljava/util/List;ZLlyiahf/vczjk/jg5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/dp8;

    move-result-object v0

    :goto_0
    return-object v0

    :cond_1
    const/16 v1, 0xd

    invoke-static {v1}, Llyiahf/vczjk/l5a;->OooO00o(I)V

    throw v0

    :cond_2
    const/16 v1, 0xc

    invoke-static {v1}, Llyiahf/vczjk/l5a;->OooO00o(I)V

    throw v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
