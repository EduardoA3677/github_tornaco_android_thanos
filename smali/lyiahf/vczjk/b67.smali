.class public final synthetic Llyiahf/vczjk/b67;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/a77;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/a77;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/b67;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/b67;->OooOOO:Llyiahf/vczjk/a77;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    iget v0, p0, Llyiahf/vczjk/b67;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v7

    iget-object p1, p0, Llyiahf/vczjk/b67;->OooOOO:Llyiahf/vczjk/a77;

    iget-object p1, p1, Llyiahf/vczjk/g39;->OooO0o0:Llyiahf/vczjk/xo8;

    iget-object p1, p1, Llyiahf/vczjk/xo8;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/sc9;

    invoke-virtual {p1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    move-object v9, v0

    check-cast v9, Llyiahf/vczjk/rs5;

    invoke-virtual {p1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/rs5;

    check-cast p1, Llyiahf/vczjk/s29;

    invoke-virtual {p1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p1

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/s67;

    const-string p1, "$this$updateState"

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v5, 0x0

    const/16 v8, 0x1ff

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v6, 0x0

    invoke-static/range {v0 .. v8}, Llyiahf/vczjk/s67;->OooO00o(Llyiahf/vczjk/s67;ZLjava/util/List;Ljava/util/List;Ljava/util/LinkedHashMap;Llyiahf/vczjk/mw;ZZI)Llyiahf/vczjk/s67;

    move-result-object p1

    check-cast v9, Llyiahf/vczjk/s29;

    invoke-virtual {v9, p1}, Llyiahf/vczjk/s29;->OooOOOO(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v6

    iget-object p1, p0, Llyiahf/vczjk/b67;->OooOOO:Llyiahf/vczjk/a77;

    iget-object p1, p1, Llyiahf/vczjk/g39;->OooO0o0:Llyiahf/vczjk/xo8;

    iget-object p1, p1, Llyiahf/vczjk/xo8;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/sc9;

    invoke-virtual {p1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    move-object v9, v0

    check-cast v9, Llyiahf/vczjk/rs5;

    invoke-virtual {p1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/rs5;

    check-cast p1, Llyiahf/vczjk/s29;

    invoke-virtual {p1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p1

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/s67;

    const-string p1, "$this$updateState"

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v5, 0x0

    const/16 v8, 0x2ff

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v7, 0x0

    invoke-static/range {v0 .. v8}, Llyiahf/vczjk/s67;->OooO00o(Llyiahf/vczjk/s67;ZLjava/util/List;Ljava/util/List;Ljava/util/LinkedHashMap;Llyiahf/vczjk/mw;ZZI)Llyiahf/vczjk/s67;

    move-result-object p1

    check-cast v9, Llyiahf/vczjk/s29;

    invoke-virtual {v9, p1}, Llyiahf/vczjk/s29;->OooOOOO(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/mw;

    const-string p1, "it"

    invoke-static {v5, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/b67;->OooOOO:Llyiahf/vczjk/a77;

    invoke-virtual {v5}, Llyiahf/vczjk/mw;->toString()Ljava/lang/String;

    iget-object v0, p1, Llyiahf/vczjk/g39;->OooO0o0:Llyiahf/vczjk/xo8;

    iget-object v0, v0, Llyiahf/vczjk/xo8;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    move-object v9, v1

    check-cast v9, Llyiahf/vczjk/rs5;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/rs5;

    check-cast v0, Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/s67;

    const-string v1, "$this$updateState"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v4, 0x0

    const/16 v8, 0x3bf

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    invoke-static/range {v0 .. v8}, Llyiahf/vczjk/s67;->OooO00o(Llyiahf/vczjk/s67;ZLjava/util/List;Ljava/util/List;Ljava/util/LinkedHashMap;Llyiahf/vczjk/mw;ZZI)Llyiahf/vczjk/s67;

    move-result-object v0

    check-cast v9, Llyiahf/vczjk/s29;

    invoke-virtual {v9, v0}, Llyiahf/vczjk/s29;->OooOOOO(Ljava/lang/Object;)V

    invoke-virtual {p1}, Llyiahf/vczjk/a77;->OooO()V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_2
    check-cast p1, Landroidx/activity/result/ActivityResult;

    const-string v0, "result"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, -0x1

    iget p1, p1, Landroidx/activity/result/ActivityResult;->OooOOO0:I

    if-ne p1, v0, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/b67;->OooOOO:Llyiahf/vczjk/a77;

    invoke-virtual {p1}, Llyiahf/vczjk/a77;->OooO()V

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
