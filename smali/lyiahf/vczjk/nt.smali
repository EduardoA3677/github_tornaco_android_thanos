.class public final synthetic Llyiahf/vczjk/nt;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/ov5;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ov5;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/nt;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/nt;->OooOOO:Llyiahf/vczjk/ov5;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    iget v0, p0, Llyiahf/vczjk/nt;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/cw5;

    const-string v0, "$this$navigate"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/nt;->OooOOO:Llyiahf/vczjk/ov5;

    iget-object v0, v0, Llyiahf/vczjk/ov5;->OooO0O0:Llyiahf/vczjk/su5;

    invoke-virtual {v0}, Llyiahf/vczjk/su5;->OooO()Llyiahf/vczjk/dv5;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/dv5;->OooOOo:Llyiahf/vczjk/rr0;

    iget-object v0, v0, Llyiahf/vczjk/rr0;->OooOOo:Ljava/lang/Object;

    check-cast v0, Ljava/lang/String;

    const/4 v1, 0x1

    if-eqz v0, :cond_1

    invoke-static {v0}, Llyiahf/vczjk/z69;->OoooOO0(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_0

    iput-object v0, p1, Llyiahf/vczjk/cw5;->OooO0o0:Ljava/lang/String;

    const/4 v0, -0x1

    iput v0, p1, Llyiahf/vczjk/cw5;->OooO0Oo:I

    iput-boolean v1, p1, Llyiahf/vczjk/cw5;->OooO0o:Z

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Cannot pop up to an empty route"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    :goto_0
    iput-boolean v1, p1, Llyiahf/vczjk/cw5;->OooO0O0:Z

    iput-boolean v1, p1, Llyiahf/vczjk/cw5;->OooO0OO:Z

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/ev5;

    const-string p1, "$this$NavHost"

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/qt;

    iget-object v10, p0, Llyiahf/vczjk/nt;->OooOOO:Llyiahf/vczjk/ov5;

    const/4 v1, 0x0

    invoke-direct {p1, v10, v1}, Llyiahf/vczjk/qt;-><init>(Llyiahf/vczjk/ov5;I)V

    new-instance v8, Llyiahf/vczjk/a91;

    const v1, -0x926d8c5

    const/4 v11, 0x1

    invoke-direct {v8, v1, p1, v11}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    const/4 v6, 0x0

    const/4 v7, 0x0

    const-string v1, "Home"

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/16 v9, 0xfe

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/rs;->OooOOOo(Llyiahf/vczjk/ev5;Ljava/lang/String;Ljava/util/List;Ljava/util/List;Llyiahf/vczjk/b2;Llyiahf/vczjk/b2;Llyiahf/vczjk/b2;Llyiahf/vczjk/b2;Llyiahf/vczjk/a91;I)V

    new-instance p1, Llyiahf/vczjk/qt;

    const/4 v1, 0x1

    invoke-direct {p1, v10, v1}, Llyiahf/vczjk/qt;-><init>(Llyiahf/vczjk/ov5;I)V

    new-instance v1, Llyiahf/vczjk/a91;

    const v2, 0x6e15cdf9

    invoke-direct {v1, v2, p1, v11}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    const-string p1, "PM"

    invoke-static {v0, p1, v1}, Llyiahf/vczjk/so8;->OooOOO(Llyiahf/vczjk/ev5;Ljava/lang/String;Llyiahf/vczjk/a91;)V

    new-instance p1, Llyiahf/vczjk/qt;

    const/4 v1, 0x2

    invoke-direct {p1, v10, v1}, Llyiahf/vczjk/qt;-><init>(Llyiahf/vczjk/ov5;I)V

    new-instance v1, Llyiahf/vczjk/a91;

    const v2, 0x73a23322

    invoke-direct {v1, v2, p1, v11}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    const-string p1, "SF"

    invoke-static {v0, p1, v1}, Llyiahf/vczjk/so8;->OooOOO(Llyiahf/vczjk/ev5;Ljava/lang/String;Llyiahf/vczjk/a91;)V

    new-instance p1, Llyiahf/vczjk/qt;

    const/4 v1, 0x3

    invoke-direct {p1, v10, v1}, Llyiahf/vczjk/qt;-><init>(Llyiahf/vczjk/ov5;I)V

    new-instance v1, Llyiahf/vczjk/a91;

    const v2, -0x2cedf1ff

    invoke-direct {v1, v2, p1, v11}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    const-string p1, "BC"

    invoke-static {v0, p1, v1}, Llyiahf/vczjk/so8;->OooOOO(Llyiahf/vczjk/ev5;Ljava/lang/String;Llyiahf/vczjk/a91;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
